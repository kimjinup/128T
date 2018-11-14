#!/usr/bin/env python3
import sys
import boto3
import argparse

def get_args():
    parser = argparse.ArgumentParser(description='Create 128T AWS instance')
    parser.add_argument('region', help='region name')
    parser.add_argument('access_key_id', help='AWS Access Key ID')
    parser.add_argument('secret_access_key', help='AWS Secrete Access Key')
    parser.add_argument('vpc_id', help='VPC ID')
    parser.add_argument('public_subnet_id', help='Public Subnet ID')
    parser.add_argument('private_subnet_id', help='Private Subnet ID')
    parser.add_argument('key_name', help='AWS Key Name')
    parser.add_argument('-n', '--name_tag', help='Name Tag')
    parser.add_argument('-o', '--owner_tag', help='Owner Tag')

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return parser.parse_args()

def get_128t_ami_id(ec2_client):
    # get the 128T platform AMI ID
    response = ec2_client.describe_images(Filters=[{'Name': 'description',
                                                    'Values': ['128T Networking Platform - CentOS7']}])
    return response['Images'][0]['ImageId']


def create_ec2_client(region_name, access_key, secret_access_key):
    return boto3.client('ec2', region_name=region_name,
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret_access_key)


def create_128t_instance(ec2_client,
                         vpc_id,
                         public_subnet_id,
                         private_subnet_id,
                         key_name,
                         name_tag,
                         owner_tag):
    public_sg_name = 'Conductor Security Group'
    private_sg_name = 'Allow All'
    public_ip_address = ''
    public_sg_id = ''
    private_sg_id = ''


    # create an EC2 client
    ec2 = ec2_client

    try:

        # create a security group for public subnets
        response = ec2.describe_security_groups()
        sgs = [sg for sg in response['SecurityGroups'] if sg['GroupName'].lower() == public_sg_name.lower()]
        if len(sgs) == 0:
            response = ec2.create_security_group(Description='Conductor Security Group for WAN side',
                                                 GroupName=public_sg_name,
                                                 VpcId=vpc_id,
                                                 DryRun=False)
            public_sg_id = response['GroupId']
            ec2.authorize_security_group_ingress(GroupId=public_sg_id,
                                                 IpPermissions=[{'FromPort': 22,
                                                                 'ToPort': 22,
                                                                 'IpProtocol': 'tcp',
                                                                 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                                                                {'FromPort': 443,
                                                                 'ToPort': 443,
                                                                 'IpProtocol': 'tcp',
                                                                 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
                                                 )
        else:
            public_sg_id = sgs[0]['GroupId']

        # create a security group for private subnets
        response = ec2.describe_security_groups()
        sgs = [sg for sg in response['SecurityGroups'] if sg['GroupName'].lower() == private_sg_name.lower()]
        if len(sgs) == 0:
            response = ec2.create_security_group(Description='Allow All',
                                                 GroupName=private_sg_name,
                                                 VpcId=vpc_id,
                                                 DryRun=False)
            private_sg_id = response['GroupId']
            ec2.authorize_security_group_ingress(GroupId=private_sg_id,
                                                 IpPermissions=[{'FromPort': -1,
                                                                 'ToPort': -1,
                                                                 'IpProtocol': '-1',
                                                                 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
                                                 )
        else:
            private_sg_id = sgs[0]['GroupId']

        # create a public network interface
        response = ec2.create_network_interface(Groups=[public_sg_id],
                                                SubnetId=public_subnet_id)
        nic0_id = response['NetworkInterface']['NetworkInterfaceId']
        ec2.modify_network_interface_attribute(NetworkInterfaceId=nic0_id, SourceDestCheck={'Value': False})

        # create a private network interface
        response = ec2.create_network_interface(Groups=[private_sg_id],
                                                SubnetId=private_subnet_id)
        nic1_id = response['NetworkInterface']['NetworkInterfaceId']
        ec2.modify_network_interface_attribute(NetworkInterfaceId=nic1_id, SourceDestCheck={'Value': False})

        # allocate an elastic address
        response = ec2.allocate_address(Domain='vpc')
        allocation_id = response['AllocationId']
        public_ip_address = response['PublicIp']

        # associate the elastic address to the network interface
        ec2.associate_address(AllocationId=allocation_id, NetworkInterfaceId=nic0_id)

        # get 128T Platform AMI ID
        ami_id = get_128t_ami_id(ec2)

        # create a router instance
        response = ec2.run_instances(ImageId=ami_id,
                                     InstanceType='t2.large',
                                     KeyName=key_name,
                                     MaxCount=1,
                                     MinCount=1,
                                     NetworkInterfaces=[{'NetworkInterfaceId': nic0_id, 'DeviceIndex': 0},
                                                        {'NetworkInterfaceId': nic1_id, 'DeviceIndex': 1}]
                                     )
        instance_id = response['Instances'][0]['InstanceId']

        ec2.create_tags(Resources=[instance_id],
                        Tags=[{'Key': 'Name', 'Value': name_tag},
                              {'Key': 'Owner', 'Value': owner_tag}]
                        )
        return {'InstanceId': instance_id, 'PublicIp': public_ip_address}

    except Exception as e:
        print(e)


if __name__ == '__main__':

    args = get_args()

    region_name = args.region
    access_key_id = args.access_key_id
    secrete_access_key = args.secret_access_key
    vpc_id = args.vpc_id
    public_subnet_id = args.public_subnet_id
    private_subnet_id = args.private_subnet_id
    key_name = args.key_name

    if args.name_tag:
        name_tag = args.name_tag
    else:
        name_tag = '128T-Platform'

    if args.owner_tag:
        owner_tag = args.owner_tag
    else:
        owner_tag = '128T Admin'

    ec2 = create_ec2_client(region_name, access_key_id, secrete_access_key)

    response = create_128t_instance(ec2, vpc_id, public_subnet_id, private_subnet_id, key_name, name_tag, owner_tag)
    print(response['InstanceId'] + ' has been created.')
    print(response['InstanceId'] + ' can be access by \"ssh t128@' + response['PublicIp'] + '\"')

