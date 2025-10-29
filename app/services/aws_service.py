import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from flask import current_app
from app.services.security_service import SecurityService
from app.models import (
    AWSCredentials, EC2Instance, VPC, Subnet, SecurityGroup, SecurityGroupRule,
    RouteTable, Route, ENI, ElasticIP, AMI, Snapshot
)
from app import db
from datetime import datetime
import dateutil.parser

def get_name_tag(tags_list):
    """Helper function to extract the 'Name' tag from a list of tags."""
    if not tags_list:
        return 'N/A'
    return next((tag['Value'] for tag in tags_list if tag['Key'] == 'Name'), 'N/A')

class AWSService:
    """
    Manages AWS connections and full inventory data fetching using boto3.
    """
    def __init__(self, aws_credentials: AWSCredentials):
        self.credentials = aws_credentials
        self.security_service = SecurityService()
        self.account_id = aws_credentials.id
        self.session = self._get_boto3_session()
        self.regions = self._get_all_regions()

        # --- THIS IS THE UPDATED LOGIC ---
        if self.credentials.default_region:
            # A specific region was provided, so only use that one.
            self.regions = [self.credentials.default_region]
            current_app.logger.info(f"Syncing specified region: {self.credentials.default_region}")
        else:
            # No region was specified, scan all regions.
            current_app.logger.info("No default region specified, scanning all regions.")
            self.regions = self._get_all_regions()
        # --- END OF UPDATED LOGIC ---

    def _get_boto3_session(self):
        """
        Creates a boto3 session based on the stored credentials.
        """
        session_params = {
            'region_name': self.credentials.default_region or current_app.config['AWS_DEFAULT_REGION']
        }
        try:
            if self.credentials.auth_type == 'iam_role':
                sts_client = boto3.client('sts')
                assumed_role_object = sts_client.assume_role(
                    RoleArn=self.credentials.role_arn,
                    RoleSessionName=f"DashboardSession-{self.credentials.account_name}"
                )
                creds = assumed_role_object['Credentials']
                session_params['aws_access_key_id'] = creds['AccessKeyId']
                session_params['aws_secret_access_key'] = creds['SecretAccessKey']
                session_params['aws_session_token'] = creds['SessionToken']
            elif self.credentials.auth_type == 'access_key':
                session_params['aws_access_key_id'] = self.credentials.aws_access_key_id
                decrypted_secret = self.security_service.decrypt_data(self.credentials.encrypted_aws_secret_access_key)
                if not decrypted_secret:
                    raise NoCredentialsError("Failed to decrypt secret key.")
                session_params['aws_secret_access_key'] = decrypted_secret
            else:
                raise ValueError(f"Unsupported auth type: {self.credentials.auth_type}")
            
            return boto3.Session(**session_params)
        
        except (ClientError, NoCredentialsError) as e:
            current_app.logger.error(f"Failed to create boto3 session for {self.credentials.account_name}: {e}")
            raise

    def _get_all_regions(self):
        """Gets a list of all available EC2 regions."""
        try:
            ec2_client = self.session.client('ec2')
            return [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        except ClientError as e:
            current_app.logger.error(f"Could not fetch AWS regions: {e}")
            return [self.credentials.default_region] # Fallback

    def sync_all_resources(self):
        """
        Main sync function to fetch all resources from all regions.
        Implements an "upsert-and-prune" strategy.
        """
        try:
            # We'll track all fetched resource IDs to prune stale ones.
            # Using sets for efficient 'in' checks.
            self.live_resource_ids = {
                'vpcs': set(), 'subnets': set(), 'sgs': set(),
                'rts': set(), 'enis': set(), 'eips': set(),
                'amis': set(), 'snapshots': set(), 'instances': set()
            }

            # Fetch resources. Order is important due to dependencies (VPC first).
            for region in self.regions:
                current_app.logger.info(f"Syncing region: {region} for account: {self.account_id}")
                ec2 = self.session.resource('ec2', region_name=region)
                ec2_client = self.session.client('ec2', region_name=region)
                
                # Networking
                self._sync_vpcs(ec2.vpcs.all(), region)
                self._sync_subnets(ec2.subnets.all(), region)
                self._sync_security_groups(ec2.security_groups.all(), region)
                self._sync_route_tables(ec2.route_tables.all(), region)
                self._sync_enis(ec2.network_interfaces.all(), region)
                self._sync_eips(ec2_client.describe_addresses().get('Addresses', []), region)
                
                # Compute & Storage
                self._sync_amis(ec2_client.describe_images(Owners=['self']).get('Images', []), region)
                self._sync_snapshots(ec2.snapshots.filter(OwnerIds=['self']).all(), region)
                self._sync_ec2_instances(ec2.instances.all(), region)

            # Prune stale resources
            self._prune_stale_resources()

            db.session.commit()
            return f"Sync Successful for {len(self.regions)} regions."
        
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Sync failed for account {self.account_id}: {e}", exc_info=True)
            return f"Sync Failed: {str(e)}"

    # --- Sync Methods (Upsert) ---

    def _sync_vpcs(self, vpcs, region):
        for v in vpcs:
            vpc = VPC.query.filter_by(vpc_id=v.id).first()
            if not vpc:
                vpc = VPC(vpc_id=v.id, aws_account_id=self.account_id)
                db.session.add(vpc)
            vpc.region = region
            vpc.cidr_block = v.cidr_block
            vpc.is_default = v.is_default
            vpc.tags = v.tags
            vpc.name = get_name_tag(v.tags)
            self.live_resource_ids['vpcs'].add(v.id)

    def _sync_subnets(self, subnets, region):
        for s in subnets:
            subnet = Subnet.query.filter_by(subnet_id=s.id).first()
            if not subnet:
                subnet = Subnet(subnet_id=s.id, aws_account_id=self.account_id)
                db.session.add(subnet)
            subnet.vpc_id_str = s.vpc_id
            subnet.region = region
            subnet.cidr_block = s.cidr_block
            subnet.availability_zone = s.availability_zone
            subnet.tags = s.tags
            subnet.name = get_name_tag(s.tags)
            self.live_resource_ids['subnets'].add(s.id)

    def _sync_security_groups(self, sgs, region):
        for s in sgs:
            sg = SecurityGroup.query.filter_by(group_id=s.id).first()
            if not sg:
                sg = SecurityGroup(group_id=s.id, aws_account_id=self.account_id)
                db.session.add(sg)
            sg.vpc_id_str = s.vpc_id
            sg.region = region
            sg.group_name = s.group_name
            sg.description = s.description
            sg.tags = s.tags
            self.live_resource_ids['sgs'].add(s.id)
            # Sync rules
            db.session.query(SecurityGroupRule).filter(SecurityGroupRule.sg_id == sg.id).delete()
            self._add_sg_rules(sg, s.ip_permissions, 'inbound')
            self._add_sg_rules(sg, s.ip_permissions_egress, 'outbound')

    def _add_sg_rules(self, sg_model, rules, rule_type):
        for rule in rules:
            for ip_range in rule.get('IpRanges', []):
                new_rule = SecurityGroupRule(
                    sg_id=sg_model.id,
                    rule_type=rule_type,
                    protocol=rule.get('IpProtocol', '-1'),
                    from_port=rule.get('FromPort'),
                    to_port=rule.get('ToPort'),
                    cidr_ipv4=ip_range.get('CidrIp')
                )
                db.session.add(new_rule)
            for user_group in rule.get('UserIdGroupPairs', []):
                new_rule = SecurityGroupRule(
                    sg_id=sg_model.id,
                    rule_type=rule_type,
                    protocol=rule.get('IpProtocol', '-1'),
                    from_port=rule.get('FromPort'),
                    to_port=rule.get('ToPort'),
                    source_security_group_id=user_group.get('GroupId')
                )
                db.session.add(new_rule)

    def _sync_route_tables(self, rts, region):
        for r in rts:
            rt = RouteTable.query.filter_by(route_table_id=r.id).first()
            if not rt:
                rt = RouteTable(route_table_id=r.id, aws_account_id=self.account_id)
                db.session.add(rt)
            rt.vpc_id_str = r.vpc_id
            rt.region = region
            rt.tags = r.tags
            rt.name = get_name_tag(r.tags)
            self.live_resource_ids['rts'].add(r.id)
            # Sync routes
            db.session.query(Route).filter(Route.route_table_id_int == rt.id).delete()
            for route in r.routes:
                new_route = Route(
                    route_table_id_int=rt.id,
                    destination_cidr=route.destination_cidr_block,
                    target_gateway_id=route.gateway_id,
                    target_instance_id=route.instance_id,
                    target_eni_id=route.network_interface_id,
                    origin=route.origin
                )
                db.session.add(new_route)

    def _sync_enis(self, enis, region):
        for e in enis:
            eni = ENI.query.filter_by(eni_id=e.id).first()
            if not eni:
                eni = ENI(eni_id=e.id, aws_account_id=self.account_id)
                db.session.add(eni)
            eni.subnet_id_str = e.subnet_id
            eni.region = region
            eni.status = e.status
            eni.description = e.description
            eni.private_ip = e.private_ip_address
            eni.public_ip = e.association_attribute.get('PublicIp') if e.association_attribute else None
            self.live_resource_ids['enis'].add(e.id)

    def _sync_eips(self, eips, region):
        for e in eips:
            eip = ElasticIP.query.filter_by(allocation_id=e.get('AllocationId')).first()
            if not eip:
                eip = ElasticIP(allocation_id=e.get('AllocationId'), aws_account_id=self.account_id)
                db.session.add(eip)
            eip.public_ip = e.get('PublicIp')
            eip.region = region
            eip.eni_id_str = e.get('NetworkInterfaceId')
            eip.instance_id_str = e.get('InstanceId')
            self.live_resource_ids['eips'].add(e.get('AllocationId'))

    def _sync_amis(self, amis, region):
        for a in amis:
            ami = AMI.query.filter_by(image_id=a.get('ImageId')).first()
            if not ami:
                ami = AMI(image_id=a.get('ImageId'), aws_account_id=self.account_id)
                db.session.add(ami)
            ami.region = region
            ami.name = a.get('Name')
            ami.creation_date = dateutil.parser.isoparse(a.get('CreationDate')) if a.get('CreationDate') else None
            ami.owner_id = a.get('OwnerId')
            ami.is_public = a.get('Public', False)
            ami.tags = a.get('Tags')
            self.live_resource_ids['amis'].add(a.get('ImageId'))

    def _sync_snapshots(self, snapshots, region):
        for s in snapshots:
            snap = Snapshot.query.filter_by(snapshot_id=s.id).first()
            if not snap:
                snap = Snapshot(snapshot_id=s.id, aws_account_id=self.account_id)
                db.session.add(snap)
            snap.region = region
            snap.volume_id = s.volume_id
            snap.start_time = s.start_time
            snap.volume_size_gb = s.volume_size
            snap.state = s.state
            snap.tags = s.tags
            self.live_resource_ids['snapshots'].add(s.id)

    def _sync_ec2_instances(self, instances, region):
        # We must commit intermediate data (VPCs, SGs, etc.)
        # so that foreign key relationships can be built.
        db.session.commit()
        
        all_sgs = SecurityGroup.query.filter_by(aws_account_id=self.account_id).all()
        sg_map = {sg.group_id: sg for sg in all_sgs}
        
        for i in instances:
            inst = EC2Instance.query.filter_by(instance_id=i.id).first()
            if not inst:
                inst = EC2Instance(instance_id=i.id, aws_account_id=self.account_id)
                db.session.add(inst)
            inst.name = get_name_tag(i.tags)
            inst.instance_type = i.instance_type
            inst.state = i.state['Name']
            inst.region = region
            inst.private_ip = i.private_ip_address
            inst.public_ip = i.public_ip_address
            inst.launch_time = i.launch_time
            inst.tags = i.tags
            inst.ami_id_str = i.image_id
            inst.vpc_id_str = i.vpc_id
            inst.subnet_id_str = i.subnet_id
            
            # Link security groups
            inst.security_groups.clear()
            for sg_ref in i.security_groups:
                sg_model = sg_map.get(sg_ref['GroupId'])
                if sg_model:
                    inst.security_groups.append(sg_model)
            
            self.live_resource_ids['instances'].add(i.id)

    # --- Prune Methods ---

    def _prune_stale_resources(self):
        """
        Deletes resources from the DB that are no longer present in AWS.
        """
        current_app.logger.info("Pruning stale resources...")
        
        # Order of deletion is important to avoid FK violations (children first)
        EC2Instance.query.filter_by(aws_account_id=self.account_id)\
            .filter(~EC2Instance.instance_id.in_(self.live_resource_ids['instances'])).delete(synchronize_session=False)
            
        Snapshot.query.filter_by(aws_account_id=self.account_id)\
            .filter(~Snapshot.snapshot_id.in_(self.live_resource_ids['snapshots'])).delete(synchronize_session=False)

        AMI.query.filter_by(aws_account_id=self.account_id)\
            .filter(~AMI.image_id.in_(self.live_resource_ids['amis'])).delete(synchronize_session=False)
            
        ElasticIP.query.filter_by(aws_account_id=self.account_id)\
            .filter(~ElasticIP.allocation_id.in_(self.live_resource_ids['eips'])).delete(synchronize_session=False)
            
        ENI.query.filter_by(aws_account_id=self.account_id)\
            .filter(~ENI.eni_id.in_(self.live_resource_ids['enis'])).delete(synchronize_session=False)
            
        # SecurityGroupRule and Route are deleted via cascade from their parents

        RouteTable.query.filter_by(aws_account_id=self.account_id)\
            .filter(~RouteTable.route_table_id.in_(self.live_resource_ids['rts'])).delete(synchronize_session=False)
            
        SecurityGroup.query.filter_by(aws_account_id=self.account_id)\
            .filter(~SecurityGroup.group_id.in_(self.live_resource_ids['sgs'])).delete(synchronize_session=False)
            
        Subnet.query.filter_by(aws_account_id=self.account_id)\
            .filter(~Subnet.subnet_id.in_(self.live_resource_ids['subnets'])).delete(synchronize_session=False)
            
        VPC.query.filter_by(aws_account_id=self.account_id)\
            .filter(~VPC.vpc_id.in_(self.live_resource_ids['vpcs'])).delete(synchronize_session=False)
        
        current_app.logger.info("Pruning complete.")