from aws_cdk import (
    # Duration,
    Stack,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_elasticloadbalancingv2 as elbv2,
    aws_elasticloadbalancingv2_targets as elbv2_targets,
    CfnOutput
)
from constructs import Construct

class CdkStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # VPC
        vpc = ec2.Vpc(self, "EngineeringVpc",
                      ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/18"),
                      max_azs=2,
                      subnet_configuration=[
                          ec2.SubnetConfiguration(name="PublicSubnet1", cidr_mask=24, subnet_type=ec2.SubnetType.PUBLIC),
                          ec2.SubnetConfiguration(name="PublicSubnet2", cidr_mask=24, subnet_type=ec2.SubnetType.PUBLIC),
                      ])

        # Security Group
        sg = ec2.SecurityGroup(self, "WebSecurityGroup",
                               vpc=vpc,
                               description="Allow SSH and HTTP access",
                               allow_all_outbound=True)
                               
        sg.add_ingress_rule(ec2.Peer.ipv4("68.59.42.90/32"), ec2.Port.tcp(22), "SSH Access")
        sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(80), "HTTP Access")
        
        # Instance Role and SSM Managed Policy
        InstanceRole = iam.Role(self, "InstanceSSM", assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"))
        InstanceRole.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"))

        # Selecting the subnets for instances and load balancer explicitly
        subnet_selection1 = ec2.SubnetSelection(subnet_group_name="PublicSubnet1")
        subnet_selection2 = ec2.SubnetSelection(subnet_group_name="PublicSubnet2")

        instance1 = ec2.Instance(self, "web1",
                                 instance_type=ec2.InstanceType("t2.micro"),
                                 machine_image=ec2.AmazonLinuxImage(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2),
                                 vpc=vpc,
                                 vpc_subnets=subnet_selection1,
                                 security_group=sg,
                                 role=InstanceRole)

        instance2 = ec2.Instance(self, "web2",
                                 instance_type=ec2.InstanceType("t2.micro"),
                                 machine_image=ec2.AmazonLinuxImage(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2),
                                 vpc=vpc,
                                 vpc_subnets=subnet_selection2,
                                 security_group=sg,
                                 role=InstanceRole)

        # Application Load Balancer
        lb = elbv2.ApplicationLoadBalancer(self, "EngineeringLB",
                                           vpc=vpc,
                                           internet_facing=True,
                                           load_balancer_name="EngineeringLB",
                                           vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC)
                                          )
                                           
        listener = lb.add_listener("Listener", port=80, open=True)
        listener.add_targets("Target",
                             port=80,
                             targets=[elbv2_targets.InstanceTarget(instance1, port=80),
                                      elbv2_targets.InstanceTarget(instance2, port=80)])
        
        # Output
        CfnOutput(self, "LoadBalancerDNS", value=lb.load_balancer_dns_name)