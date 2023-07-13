import boto3
import click

# get data from all regions
class aws:
    def dns(accounts, iamrole):
        dnsdata = []
        for aws_account in accounts:
            click.echo("Reading DNS data from AWS Account - " + str(aws_account))
            if len(str(aws_account)) == 12:
                sts_client = boto3.client('sts')
                assume_role_object = sts_client.assume_role(RoleArn=f'arn:aws:iam::{aws_account}:role/{iamrole}', RoleSessionName='findmytakeover')
                credentials = assume_role_object['Credentials']

                client = boto3.client('route53', aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'])
                response = client.list_hosted_zones()['HostedZones']

                for i in response:
                    if i['Config']['PrivateZone'] is False:
                        record = client.list_resource_record_sets(HostedZoneId=i['Id'])['ResourceRecordSets']
                        for j in record:
                            if j['Type'] == "A" or j['Type'] == "AAAA" or j['Type'] == "CNAME":
                                if j.get('ResourceRecords') is not None:
                                    for k in j.get('ResourceRecords'):
                                        dnsdata.append([aws_account, j['Name'], k['Value']])

                                if j.get('AliasTarget') is not None:
                                    dnsdata.append([aws_account, j['Name'], j.get('AliasTarget')['DNSName']])
            else:
                click.echo(f'Please check the AWS Account number {aws_account}. It does seem to be valid.')
        return dnsdata

    def infra(accounts, iamrole):
        infradata = []
        for aws_account in accounts:
            click.echo("Getting Infrastructure details from AWS Account - " + str(aws_account))
            regions = []
            if len(str(aws_account)) == 12: 
                sts_client = boto3.client('sts')
                assume_role_object = sts_client.assume_role(RoleArn=f'arn:aws:iam::{aws_account}:role/{iamrole}', RoleSessionName='findmytakeover')
                credentials = assume_role_object['Credentials']

                ec2_client = boto3.client('ec2', aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'])
                response = ec2_client.describe_regions()
                for i in response['Regions']:
                    regions.append(i['RegionName'])

                # Collect dynamically assigned IP Address as well and not just IP Address and
                for r in regions:
                    try:
                        ec2_client = boto3.client('ec2', aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'], region_name=r)
                        addresses_dict = ec2_client.describe_instances()
                        for i in addresses_dict['Reservations']:
                            for j in i['Instances']:
                                for b in j['NetworkInterfaces']:
                                    if 'Association' in b:
                                        infradata.append([aws_account, 'ec2-ip', b['Association']['PublicIp']])
                                        infradata.append([aws_account, 'ec2-ip', b['Association']['PublicDnsName']])
                        
                        elb_client = boto3.client('elb', aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'], region_name=r)
                        response = elb_client.describe_load_balancers()
                        for i in response['LoadBalancerDescriptions']:
                            if i['Scheme'] == 'internet-facing':
                                infradata.append([aws_account, 'elb', i['DNSName']])

                        client = boto3.client('cloudfront', aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'], region_name=r)
                        response = client.list_distributions()
                        for i in response['DistributionList']['Items']:
                            infradata.append([aws_account, 'cloudront', i['DomainName']])

                        client = boto3.client('s3', aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'], region_name=r)
                        response = client.list_buckets()
                        for i in response['Buckets']:
                            infradata.append([aws_account, 'cloudront', i['Name']])

                        client = boto3.client('rds', aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'], region_name=r)
                        response = client.describe_db_instances()
                        for i in response['DBInstances']:
                            infradata.append([aws_account, 'rds', i['Endpoint']['Address']])
                        
                        # Collect ES DNS Address
                        client = boto3.client('opensearch', aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'], region_name=r)
                        response = client.list_domain_names(EngineType='OpenSearch') #|'Elasticsearch'
                        for i in response['DomainNames']:
                            result = client.describe_domain(DomainName=i['DomainName'])
                            print(result['DomainStatus']['Endpoint'])
                        
                        response = client.list_domain_names(EngineType='Elasticsearch')
                        for i in response['DomainNames']:
                            result = client.describe_domain(DomainName=i['DomainName'])
                            print(result['DomainStatus']['Endpoint'])

                        # Collect API Gateway
                        client = boto3.client('apigatewayv2', aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'], region_name=r)
                        response = client.get_apis()
                        print(response)
                        
                        # TODO - Implement colletor for the following services. 

                        # Collect AWS BeanStalk
                        # Collect AWS Congnito
                        # Collect ELBv2

                        click.echo("Completed collecting Infrastructure details from the account -  " + str(aws_account) + "in the region - " + r)
                    except KeyError:
                        continue
            else:
                print(f'Please check the AWS Account number {str(aws_account)}. It does seem to be valid.')
        return infradata