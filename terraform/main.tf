resource "aws_key_pair" "cyberwolves" {
    key_name = "cyberwolves"
    public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINoO1eDqpqnkbrDXw5MrZru+F/FgE8jtXnSoV6X8DMxQ"

    tags = {
        Name = "cyberwolves"
    }
}

resource "aws_iam_role" "ec2_role" {
    name = "ec2role"
    assume_role_policy = jsonencode({
        Version: "2012-10-17",
        Statement: [
            {
                Effect: "Allow",
                Principal: {
                    Service: "ec2.amazonaws.com"
                },
                Action: "sts:AssumeRole"
            }
        ]
    })
}

data "aws_iam_policy_document" "ecr_policy" {
    statement {
        actions = [
            "ecr:GetAuthorizationToken",
            "ecr:GetDownloadUrlForLayer",
            "ecr:GetRepositoryPolicy",
            "ecr:DescribeRepositories",
            "ecr:BatchGetImage",
            "ecr:ListImages",
            "ecr:DescribeImages",
            "ecr:BatchCheckLayerAvailability",
            "ecr:PutImage",
            "ecr:InitiateLayerUpload",
            "ecr:UploadLayerPart",
            "ecr:CompleteLayerUpload"
        ]

        resources = ["*"]
    }
}

resource "aws_iam_policy" "ecr_access" {
    name = "ecr_access_policy"
    description = "Policy to access ECR registry"
    policy = data.aws_iam_policy_document.ecr_policy.json
}

resource "aws_iam_role_policy_attachment" "ecr_access_attachment" {
    role = aws_iam_role.ec2_role.name
    policy_arn = aws_iam_policy.ecr_access.arn

    depends_on = [ aws_iam_policy.ecr_access, aws_iam_role.ec2_role ]
}

resource "aws_iam_instance_profile" "ec2_ecr_instance_profile" {
    name = "ec2_ecr_role"
    role = aws_iam_role.ec2_role.name
}

resource "aws_instance" "vulnnodeapp" {
    ami = "ami-04b70fa74e45c3917"
    instance_type = "t2.nano"

    associate_public_ip_address = true
    iam_instance_profile = aws_iam_instance_profile.ec2_ecr_instance_profile.name
    key_name = "cyberwolves"

    user_data = <<-EOF
                #!/bin/bash
                sudo apt-get update
                sudo apt-get install ca-certificates curl unzip -y
                curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
                unzip awscliv2.zip
                sudo ./aws/install
                sudo install -m 0755 -d /etc/apt/keyrings
                sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
                sudo chmod a+r /etc/apt/keyrings/docker.asc
                
                echo \
                    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
                    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
                    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
                sudo apt-get update

                sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

                aws ecr get-login-password |docker login --username AWS --password-stdin 047527637988.dkr.ecr.us-east-1.amazonaws.com/n5-vulnnodeapp

                docker run -d -p 80:3000 --name vulnnodeapp 047527637988.dkr.ecr.us-east-1.amazonaws.com/n5-vulnnodeapp:latest
                
                EOF

    depends_on = [ aws_key_pair.cyberwolves, aws_iam_role.ec2_role, aws_iam_policy.ecr_access, aws_iam_role_policy_attachment.ecr_access_attachment, aws_iam_instance_profile.ec2_ecr_instance_profile ]
    
    tags = {
        Name = "vulnnodeapp"
    }
}

output "ec2_global_ips" {
  value = aws_instance.vulnnodeapp.public_ip
}