# N5 SSR Cybersecurity Challenge

Para completar este challenge, he decidido utilizar todas las herramientas 
que brinda AWS tal como lo es: 
- AWS CodeCommit
- AWS CodePipeline
- AWS CodeBuild
- AWS CodeDeploy
- AWS CodeGuru
- AWS ECR Scan
- AWS Secrets Manager
- AWS Security Hub

## Passos a Seguir

### Crear un repositorio en CodeCommit
Teniendo el `awscli` configurado con mis variables de ambiente, utilize 
los siguientes comandos en un bash script:

```
#!/bin/bash

# Create the CodeCommit Reppository and Fetch SSH URL
ssh_url=$(aws codecommit create-repository --repository-name n5-test --output yaml |grep cloneUrlSsh | awk -F" " '{print $2}')

# Create ssh-keygen
ssh-keygen -t rsa -b 2048 -C "n5-test" -f ~/.ssh/n5-test -N ""

# Add the SSH Key to the AWS CodeCommit
user=$(aws iam get-user --output yaml |grep UserName | awk -F" " '{print $2}')
ssh_user=$(aws iam upload-ssh-public-key --user-name $user --ssh-public-key-body file://~/.ssh/n5-test.pub --output yaml |grep SSHPublicKeyId | awk -F" " '{print $2}')

echo "================================"

echo "SSH URL: $ssh_url"
echo "SSH User: $ssh_user"
```

Una vez creado el repositorio, procedo a actualizar el `git url` y preparar mi `ssh-agent` para autenticacion.

```
# agregar al ~/.ssh/config lo siguiente:
Host git-codecommit.us-east-1.amazonaws.com
  AddKeysToAgent yes
  User <ssh_user>
  IdentityFile ~/.ssh/n5-test
```

### Clonar Repositorio
```
git clone https://github.com/4auvar/VulnNodeApp

git remote set-url origin <ssh_url>
```

### Crear un Pipeline con CodePipeline

- Crear el pipeline para el n5-vulnnodeapp por medio de la consola:
  - En la consola de AWS, se navega hasta CodePipeline
  - Crear nuevo pipeline y configurarlo con los siguientes pasos:
    - __Source__: Seleccionar CodeCommit y el repositorio creado.
    - __Build__: 