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
    - __Build__: Utilizar un buildspec.yaml para definir todos los pasos 
        del build pipeline con AWS CodeBuild, donde se incluyen los escaneos 
        de dependencias, SAST, y secrets. Se utiliza snyk y bearer cli.
        - Crear un container de docker con la app utilizando comando de docker,
          y crear un repositorio en ECR para guardar la imagen.
    - __Deploy__: Usar terraform para crear el EC2 t2.nano instance, instalarle docker y correr el container.


### Vulnerabilidades
__Dependencias__ 

```
Tested 141 dependencies for known issues, found 7 issues, 8 vulnerable paths. 

Issues to fix by upgrading:

  Upgrade ejs@2.6.2 to ejs@3.1.7 to fix

  ✗ Arbitrary Code Injection [Medium Severity][https://security.snyk.io/vuln/SNYK-JS-EJS-1049328] in ejs@2.6.2
    introduced by ejs@2.6.2

  ✗ Remote Code Execution (RCE) [High Severity][https://security.snyk.io/vuln/SNYK-JS-EJS-2803307] in ejs@2.6.2
    introduced by ejs@2.6.2

 Upgrade express@4.16.4 to express@4.19.2 to fix

  ✗ Open Redirect [Medium Severity][https://security.snyk.io/vuln/SNYK-JS-EXPRESS-6474509] in express@4.16.4
    introduced by express@4.16.4

  ✗ Prototype Poisoning [High Severity][https://security.snyk.io/vuln/SNYK-JS-QS-3153490] in qs@6.5.2
    introduced by express@4.16.4 > qs@6.5.2 and 1 other path(s)

  Upgrade passport@0.4.1 to passport@0.6.0 to fix

  ✗ Session Fixation [Medium Severity][https://security.snyk.io/vuln/SNYK-JS-PASSPORT-2840631] in passport@0.4.1
    introduced by passport@0.4.1

Issues with no direct upgrade or patch:

  ✗ Missing Release of Resource after Effective Lifetime [Medium Severity][https://security.snyk.io/vuln/SNYK-JS-INFLIGHT-6095116] in inflight@1.0.6
    introduced by libxmljs@0.19.10 > @mapbox/node-pre-gyp@1.0.11 > rimraf@3.0.2 > glob@7.2.3 > inflight@1.0.6

  No upgrade or patch available

  ✗ Arbitrary Code Execution [Critical Severity][https://security.snyk.io/vuln/npm:node-serialize:20170208] in node-serialize@0.0.4
    introduced by node-serialize@0.0.4

  No upgrade or patch available
```

__SAST__ 

```
85 checks, 158 findings

CRITICAL: 7 (CWE-319, CWE-78, CWE-798, CWE-89)
HIGH: 45 (CWE-22, CWE-73, CWE-79)
MEDIUM: 63 (CWE-1004, CWE-1333, CWE-208, CWE-601, CWE-614, CWE-693)
LOW: 43 (CWE-330, CWE-532)
WARNING: 0

Rules: 
https://docs.bearer.com/reference/rules [v0.36.0]
Language    Default Rules  Custom Rules  Files  
JavaScript  85             0             2232   



CRITICAL: Usage of hard-coded secret [CWE-798]
https://docs.bearer.com/reference/rules/javascript_express_hardcoded_secret
To ignore this finding, run: bearer ignore add 0ec5e66841ef7956aa183e4b3116ad93_0
File: app.js:24
 24 app.use(session({
 25   secret: 'secrettobechanged',
 26   resave: true,
 27   saveUninitialized: true,
 28   cookie: { httpOnly: false, secure: false }
 29 }))


CRITICAL: Missing secure HTTP server configuration [CWE-319]
https://docs.bearer.com/reference/rules/javascript_express_https_protocol_missing
To ignore this finding, run: bearer ignore add 747ee7aa13d386a627c3245715b1dba4_0
File: bin/www:22
 22 var server = http.createServer(app);


CRITICAL: Unsanitized dynamic input in OS command [CWE-78]
https://docs.bearer.com/reference/rules/javascript_lang_os_command_injection
To ignore this finding, run: bearer ignore add 3c8307268a30c53e92fab4e7d412c5c0_0
File: utils/utility.js:66
 66         exec(command, (err, stdout, stderr) => {
 67             if (err) {
 68                 return reject(err);
                ...omitted (buffer value 3)
 70                 return resolve(stdout);
 71             }
 72         });


CRITICAL: Usage of hard-coded secret [CWE-798]
https://docs.bearer.com/reference/rules/javascript_lang_hardcoded_secret
To ignore this finding, run: bearer ignore add b81c4d905845a863c2dbafe210ba6610_0
File: app.js:25
 25   secret: 'secrettobechanged',


CRITICAL: Usage of hard-coded secret [CWE-798]
https://docs.bearer.com/reference/rules/javascript_lang_hardcoded_secret
To ignore this finding, run: bearer ignore add a964f63435b8392558f2bb1d5dfede03_0
File: models/usersModel.js:84
 84     changePassword: "update users set password=? where id=?"


CRITICAL: Unsanitized input in SQL query [CWE-89]
https://docs.bearer.com/reference/rules/javascript_lang_sql_injection
To ignore this finding, run: bearer ignore add ee7db715c4cdb266d71f3a4042bc0782_0
File: utils/mysqlConnectionPool.js:14
 14         pool.query(query, parameters, (err, res) => {
 15             if (err) {
 16                 return reject(err);
                ...omitted (buffer value 3)
 18                 resolve(res);
 19             }
 20         });


CRITICAL: Unsanitized input in SQL query [CWE-89]
https://docs.bearer.com/reference/rules/javascript_lang_sql_injection
To ignore this finding, run: bearer ignore add ee7db715c4cdb266d71f3a4042bc0782_1
File: utils/mysqlConnectionPool.js:26
 26         pool.query(query, (err, res) => {
 27             if (err) {
 28                 return reject(err);
                ...omitted (buffer value 3)
 30                 return resolve(res);
 31             }
 32         });


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 3200ae924f995483e072a30a75014bb3_0
File: public/plugins/bootstrap-switch/js/bootstrap-switch.js:570
 570         this.$on.replaceWith($off);


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 3200ae924f995483e072a30a75014bb3_1
File: public/plugins/bootstrap-switch/js/bootstrap-switch.js:571
 571         this.$off.replaceWith($on);


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add ff56036ffaba779117e42e31143ee3fb_0
File: public/plugins/bs-custom-file-input/bs-custom-file-input.js:54
 54       element.innerHTML = defaultText;


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add ff56036ffaba779117e42e31143ee3fb_1
File: public/plugins/bs-custom-file-input/bs-custom-file-input.js:85
 85         element.innerHTML = inputValue;


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 6eb65d51f1fb1984d21aae42b809be55_0
File: public/plugins/datatables-buttons/js/buttons.print.js:152
 152            win.document.head.innerHTML = head; // Work around for Edge


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 6eb65d51f1fb1984d21aae42b809be55_1
File: public/plugins/datatables-buttons/js/buttons.print.js:159
 159        win.document.body.innerHTML =
 160            '<h1>'+exportInfo.title+'</h1>'+
 161            '<div>'+(exportInfo.messageTop || '')+'</div>'+
 162            html+
 163            '<div>'+(exportInfo.messageBottom || '')+'</div>';


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add ae801bf4431002ddd850e3229c728f55_0
File: public/plugins/datatables-buttons/js/dataTables.buttons.js:1899
 1899           _exportTextarea.innerHTML = str;


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 731ae77af746c285186962e3b2e899bb_0
File: public/plugins/daterangepicker/daterangepicker.js:158
 158                 elem.innerHTML = options.locale.customRangeLabel;


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 731ae77af746c285186962e3b2e899bb_1
File: public/plugins/daterangepicker/daterangepicker.js:346
 346                 elem.innerHTML = range;


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 32435afb16f965f423c5fa8c27ba9369_0
File: public/plugins/fullcalendar-timegrid/main.esm.js:572
 572         this.slatContainerEl.innerHTML =
 573             '<table class="' + theme.getClass('tableGrid') + '">' +
 574                 this.renderSlatRowHtml(dateProfile) +
 575                 '</table>';


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 32435afb16f965f423c5fa8c27ba9369_1
File: public/plugins/fullcalendar-timegrid/main.esm.js:619
 619         this.rootBgContainerEl.innerHTML =
 620             '<table class="' + theme.getClass('tableGrid') + '">' +
 621                 bgRow.renderHtml({
                         ...omitted (buffer value 3)
 624                     renderIntroHtml: this.renderProps.renderBgIntroHtml
 625                 }) +
 626                 '</table>';


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 22ba6ddc1f3bf67612f01d6ce32d5fb1_0
File: public/plugins/fullcalendar-timegrid/main.js:575
 575             this.slatContainerEl.innerHTML =
 576                 '<table class="' + theme.getClass('tableGrid') + '">' +
 577                     this.renderSlatRowHtml(dateProfile) +
 578                     '</table>';


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 22ba6ddc1f3bf67612f01d6ce32d5fb1_1
File: public/plugins/fullcalendar-timegrid/main.js:622
 622             this.rootBgContainerEl.innerHTML =
 623                 '<table class="' + theme.getClass('tableGrid') + '">' +
 624                     bgRow.renderHtml({
                             ...omitted (buffer value 3)
 627                         renderIntroHtml: this.renderProps.renderBgIntroHtml
 628                     }) +
 629                     '</table>';


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add a0ae5fcb0d6e23f12c97a797eb11e6ee_0
File: public/plugins/jqvmap/jquery.vmap.js:24
 24         return document.createElement('<rvml:' + tagName + ' class="rvml">');


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add a0ae5fcb0d6e23f12c97a797eb11e6ee_1
File: public/plugins/jqvmap/jquery.vmap.js:28
 28         return document.createElement('<' + tagName + ' xmlns="urn:schemas-microsoft.com:vml" class="rvml">');


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 99f580b7a942ceb76eec6233f727f2d5_0
File: public/plugins/jsgrid/jsgrid.js:1114
 1114             this._filterRow.replaceWith($filterRow);


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 99f580b7a942ceb76eec6233f727f2d5_1
File: public/plugins/jsgrid/jsgrid.js:1207
 1207             this._insertRow.replaceWith(insertRow);


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 99f580b7a942ceb76eec6233f727f2d5_2
File: public/plugins/jsgrid/jsgrid.js:1332
 1332             $updatingRow.replaceWith($updatedRow);


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 86fd4bcb5168b11ae4b099655543b876_0
File: public/plugins/plugins/bootstrap-switch/js/bootstrap-switch.js:570
 570         this.$on.replaceWith($off);


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 86fd4bcb5168b11ae4b099655543b876_1
File: public/plugins/plugins/bootstrap-switch/js/bootstrap-switch.js:571
 571         this.$off.replaceWith($on);


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 2a2372bb10e1a147181c475215ffd128_0
File: public/plugins/plugins/bs-custom-file-input/bs-custom-file-input.js:54
 54       element.innerHTML = defaultText;


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 2a2372bb10e1a147181c475215ffd128_1
File: public/plugins/plugins/bs-custom-file-input/bs-custom-file-input.js:85
 85         element.innerHTML = inputValue;


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 68d2bb55ec709c7218716d32ef8c1d1e_0
File: public/plugins/plugins/datatables-buttons/js/buttons.print.js:152
 152            win.document.head.innerHTML = head; // Work around for Edge


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 68d2bb55ec709c7218716d32ef8c1d1e_1
File: public/plugins/plugins/datatables-buttons/js/buttons.print.js:159
 159        win.document.body.innerHTML =
 160            '<h1>'+exportInfo.title+'</h1>'+
 161            '<div>'+(exportInfo.messageTop || '')+'</div>'+
 162            html+
 163            '<div>'+(exportInfo.messageBottom || '')+'</div>';


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add e28e6a609e5c186500634d2604b1aac7_0
File: public/plugins/plugins/datatables-buttons/js/dataTables.buttons.js:1899
 1899           _exportTextarea.innerHTML = str;


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 5a926d5dd1272270f5e2e50699292cfb_0
File: public/plugins/plugins/daterangepicker/daterangepicker.js:158
 158                 elem.innerHTML = options.locale.customRangeLabel;


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 5a926d5dd1272270f5e2e50699292cfb_1
File: public/plugins/plugins/daterangepicker/daterangepicker.js:346
 346                 elem.innerHTML = range;


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 2bce857a78dd96ceee07b9ab97dbc5ac_0
File: public/plugins/plugins/fullcalendar-timegrid/main.esm.js:572
 572         this.slatContainerEl.innerHTML =
 573             '<table class="' + theme.getClass('tableGrid') + '">' +
 574                 this.renderSlatRowHtml(dateProfile) +
 575                 '</table>';


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 2bce857a78dd96ceee07b9ab97dbc5ac_1
File: public/plugins/plugins/fullcalendar-timegrid/main.esm.js:619
 619         this.rootBgContainerEl.innerHTML =
 620             '<table class="' + theme.getClass('tableGrid') + '">' +
 621                 bgRow.renderHtml({
                         ...omitted (buffer value 3)
 624                     renderIntroHtml: this.renderProps.renderBgIntroHtml
 625                 }) +
 626                 '</table>';


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 46d746426c9015b5b3cc2541a0c4d645_0
File: public/plugins/plugins/fullcalendar-timegrid/main.js:575
 575             this.slatContainerEl.innerHTML =
 576                 '<table class="' + theme.getClass('tableGrid') + '">' +
 577                     this.renderSlatRowHtml(dateProfile) +
 578                     '</table>';


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 46d746426c9015b5b3cc2541a0c4d645_1
File: public/plugins/plugins/fullcalendar-timegrid/main.js:622
 622             this.rootBgContainerEl.innerHTML =
 623                 '<table class="' + theme.getClass('tableGrid') + '">' +
 624                     bgRow.renderHtml({
                             ...omitted (buffer value 3)
 627                         renderIntroHtml: this.renderProps.renderBgIntroHtml
 628                     }) +
 629                     '</table>';


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 830f580eda5914ec9e9e353045c8d2a5_0
File: public/plugins/plugins/jqvmap/jquery.vmap.js:24
 24         return document.createElement('<rvml:' + tagName + ' class="rvml">');


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add 830f580eda5914ec9e9e353045c8d2a5_1
File: public/plugins/plugins/jqvmap/jquery.vmap.js:28
 28         return document.createElement('<' + tagName + ' xmlns="urn:schemas-microsoft.com:vml" class="rvml">');


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add c61f8ea49802228afe25ae63b94b6097_0
File: public/plugins/plugins/jsgrid/jsgrid.js:1114
 1114             this._filterRow.replaceWith($filterRow);


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add c61f8ea49802228afe25ae63b94b6097_1
File: public/plugins/plugins/jsgrid/jsgrid.js:1207
 1207             this._insertRow.replaceWith(insertRow);


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add c61f8ea49802228afe25ae63b94b6097_2
File: public/plugins/plugins/jsgrid/jsgrid.js:1332
 1332             $updatingRow.replaceWith($updatedRow);


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add b9dac2949fb6f40e33013884813ce827_0
File: public/plugins/plugins/raphael/dev/raphael.vml.js:919
 919                     return doc.createElement('<rvml:' + tagName + ' class="rvml">');


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add b9dac2949fb6f40e33013884813ce827_1
File: public/plugins/plugins/raphael/dev/raphael.vml.js:923
 923                     return doc.createElement('<' + tagName + ' xmlns="urn:schemas-microsoft.com:vml" class="rvml">');


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add d5e13b4885f25654b977facf8ecfe6ca_0
File: public/plugins/raphael/dev/raphael.vml.js:919
 919                     return doc.createElement('<rvml:' + tagName + ' class="rvml">');


HIGH: Unsanitized user input in dynamic HTML insertion (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html
To ignore this finding, run: bearer ignore add d5e13b4885f25654b977facf8ecfe6ca_1
File: public/plugins/raphael/dev/raphael.vml.js:923
 923                     return doc.createElement('<' + tagName + ' xmlns="urn:schemas-microsoft.com:vml" class="rvml">');


HIGH: Usage of manual HTML sanitization (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_manual_html_sanitization
To ignore this finding, run: bearer ignore add 8ef2f83b6dddeedadad2a814c62d2f95_0
File: public/plugins/flot-old/excanvas.js:90
 90     return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;');


HIGH: Usage of manual HTML sanitization (XSS) [CWE-79]
https://docs.bearer.com/reference/rules/javascript_lang_manual_html_sanitization
To ignore this finding, run: bearer ignore add 93ff8f7e6836c2ad1220f4ceb73d70ea_0
File: public/plugins/plugins/flot-old/excanvas.js:90
 90     return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;');


HIGH: Unsanitized dynamic input in file path [CWE-73]
https://docs.bearer.com/reference/rules/javascript_lang_non_literal_fs_filename
To ignore this finding, run: bearer ignore add 4be761eacf8f5aba1808d372e4ef4d82_0
File: utils/utility.js:81
 81         fs.readFile(filePath, { encoding: 'utf-8' }, function (err, data) {
 82             if (!err) {
 83                 resolve(data);
                ...omitted (buffer value 3)
 85                 reject(err);
 86             }
 87         });


HIGH: Unsanitized dynamic input in file path [CWE-73]
https://docs.bearer.com/reference/rules/javascript_lang_non_literal_fs_filename
To ignore this finding, run: bearer ignore add 4be761eacf8f5aba1808d372e4ef4d82_1
File: utils/utility.js:98
 98         fs.readFile(filePath, { encoding: 'utf-8' }, function (err, data) {
 99             if (!err) {
 100                 let resp = "";
                     ...omitted (buffer value 3)
 111                 reject(err);
 112             }
 113         });


HIGH: Unsanitized dynamic input in file path [CWE-22]
https://docs.bearer.com/reference/rules/javascript_lang_path_traversal
To ignore this finding, run: bearer ignore add 48bff1287b5cd165eddb78c563596c85_0
File: utils/utility.js:80
 80         filePath = path.join(__dirname, filename);


MEDIUM: Missing HTTP Only option in cookie configuration [CWE-1004]
https://docs.bearer.com/reference/rules/javascript_express_cookie_missing_http_only
To ignore this finding, run: bearer ignore add 8ada50c4c60389ae462a22e9ddce7ec3_0
File: app.js:24
 24 app.use(session({
 25   secret: 'secrettobechanged',
 26   resave: true,
 27   saveUninitialized: true,
 28   cookie: { httpOnly: false, secure: false }
 29 }))


MEDIUM: Usage of default cookie configuration [CWE-693]
https://docs.bearer.com/reference/rules/javascript_express_default_cookie_config
To ignore this finding, run: bearer ignore add cfe858e6b20122a91e03221f745c9dcb_0
File: app.js:28
 28   cookie: { httpOnly: false, secure: false }


MEDIUM: Usage of default session cookie configuration [CWE-693]
https://docs.bearer.com/reference/rules/javascript_express_default_session_config
To ignore this finding, run: bearer ignore add 03ff68c49b60ef34aa387a5058c1dc7d_0
File: app.js:24
 24 app.use(session({
 25   secret: 'secrettobechanged',
 26   resave: true,
 27   saveUninitialized: true,
 28   cookie: { httpOnly: false, secure: false }
 29 }))


MEDIUM: Missing Helmet configuration on HTTP headers [CWE-693]
https://docs.bearer.com/reference/rules/javascript_express_helmet_missing
To ignore this finding, run: bearer ignore add ceb9f97741f7686615f69620a8ec2025_0
File: app.js:12
 12 var app = express();


MEDIUM: Missing Secure option in cookie configuration [CWE-614]
https://docs.bearer.com/reference/rules/javascript_express_insecure_cookie
To ignore this finding, run: bearer ignore add 0b85411cd2e54812bf0a6d2a71f67c90_0
File: app.js:24
 24 app.use(session({
 25   secret: 'secrettobechanged',
 26   resave: true,
 27   saveUninitialized: true,
 28   cookie: { httpOnly: false, secure: false }
 29 }))


MEDIUM: Unsanitized user input in redirect [CWE-601]
https://docs.bearer.com/reference/rules/javascript_express_open_redirect
To ignore this finding, run: bearer ignore add d5ae9544c791ce8ab9fa226e089de6c7_0
File: routes/users/user.js:43
 43                 res.redirect("/error-based-sqli?id=" + req.query.id + "&default=English")


MEDIUM: Unsanitized user input in redirect [CWE-601]
https://docs.bearer.com/reference/rules/javascript_express_open_redirect
To ignore this finding, run: bearer ignore add d5ae9544c791ce8ab9fa226e089de6c7_1
File: routes/users/user.js:220
 220                 res.redirect("/idor?id=" + req.query.id + "&default=English&page=idor")


MEDIUM: Missing server configuration to reduce server fingerprinting [CWE-693]
https://docs.bearer.com/reference/rules/javascript_express_reduce_fingerprint
To ignore this finding, run: bearer ignore add 56b4b80441669f82df897f20ddcfb1a9_0
File: app.js:12
 12 var app = express();


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add d45168b6f3061b8bf3c4251a1cf05acc_0
File: public/plugins/ekko-lightbox/ekko-lightbox.js:498
 498                if (typeof match[2] === "string" && match[2].length > 0 && match[2].replace(new RegExp(':(' + ({
 499                    "http:": 80,
 500                    "https:": 443
 501                })[location.protocol] + ')?$'), "") !== location.host) return true;


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add f59d2fc882aaa21d5696dbc77c70fb27_0
File: public/plugins/inputmask/inputmask/inputmask.date.extensions.js:83
 83             opts.tokenizer = new RegExp(opts.tokenizer, "g");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add e9d4628277cc084e08ed8ca080cdd869_0
File: public/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:197
 197                 processValue = processValue.replace(new RegExp(Inputmask.escapeRegex(opts.groupSeparator), "g"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add e9d4628277cc084e08ed8ca080cdd869_1
File: public/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:198
 198                 processValue = processValue.replace(new RegExp("[-" + Inputmask.escapeRegex(opts.negationSymbol.front) + "]", "g"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add e9d4628277cc084e08ed8ca080cdd869_2
File: public/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:199
 199                 processValue = processValue.replace(new RegExp(Inputmask.escapeRegex(opts.negationSymbol.back) + "$"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add e9d4628277cc084e08ed8ca080cdd869_3
File: public/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:201
 201                     processValue = processValue.replace(new RegExp(Inputmask.escapeRegex(opts.placeholder), "g"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add e9d4628277cc084e08ed8ca080cdd869_4
File: public/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:283
 283                             opts.min = opts.min.toString().replace(new RegExp(Inputmask.escapeRegex(opts.groupSeparator), "g"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add e9d4628277cc084e08ed8ca080cdd869_5
File: public/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:289
 289                             opts.max = opts.max.toString().replace(new RegExp(Inputmask.escapeRegex(opts.groupSeparator), "g"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add e9d4628277cc084e08ed8ca080cdd869_6
File: public/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:347
 347                     return emptyCheck ? new RegExp("[" + Inputmask.escapeRegex(opts.negationSymbol.front) + "+]?") : new RegExp("[" + Inputmask.escapeRegex(opts.negationSymbol.front) + "+]?\\d+");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add e9d4628277cc084e08ed8ca080cdd869_7
File: public/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:350
 350                     return new RegExp("[\\d" + Inputmask.escapeRegex(opts.groupSeparator) + Inputmask.escapeRegex(opts.placeholder.charAt(0)) + "]+");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add e9d4628277cc084e08ed8ca080cdd869_8
File: public/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:371
 371                         isValid = strict ? new RegExp("[0-9" + Inputmask.escapeRegex(opts.groupSeparator) + "]").test(chrs) : new RegExp("[0-9]").test(chrs);


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add e9d4628277cc084e08ed8ca080cdd869_9
File: public/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:375
 375                                 processValue = processValue.replace(new RegExp("[-" + Inputmask.escapeRegex(opts.negationSymbol.front) + "]", "g"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add e9d4628277cc084e08ed8ca080cdd869_10
File: public/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:376
 376                                 processValue = processValue.replace(new RegExp(Inputmask.escapeRegex(opts.negationSymbol.back) + "$"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add e9d4628277cc084e08ed8ca080cdd869_11
File: public/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:435
 435                         var isValid = new RegExp(radix).test(chrs);


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add e9d4628277cc084e08ed8ca080cdd869_12
File: public/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:455
 455                 processValue = processValue.replace(new RegExp(Inputmask.escapeRegex(opts.groupSeparator), "g"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add e9d4628277cc084e08ed8ca080cdd869_13
File: public/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:461
 461                     processValue = processValue.replace(new RegExp("^" + Inputmask.escapeRegex(opts.negationSymbol.front)), "-");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add e9d4628277cc084e08ed8ca080cdd869_14
File: public/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:462
 462                     processValue = processValue.replace(new RegExp(Inputmask.escapeRegex(opts.negationSymbol.back) + "$"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add e9d4628277cc084e08ed8ca080cdd869_15
File: public/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:469
 469                 maskedValue = maskedValue.replace(new RegExp("^" + Inputmask.escapeRegex(opts.negationSymbol.front)), "-");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add e9d4628277cc084e08ed8ca080cdd869_16
File: public/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:470
 470                 maskedValue = maskedValue.replace(new RegExp(Inputmask.escapeRegex(opts.negationSymbol.back) + "$"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add e9d4628277cc084e08ed8ca080cdd869_17
File: public/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:473
 473                 maskedValue = maskedValue.replace(new RegExp(Inputmask.escapeRegex(opts.groupSeparator) + "([0-9]{3})", "g"), "$1");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add d34a406e39b290ba655af18cba422ec3_0
File: public/plugins/jquery-validation/additional-methods.js:103
 103            regex = new RegExp( ".?(" + typeParam + ")$", "i" );


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add d34a406e39b290ba655af18cba422ec3_1
File: public/plugins/jquery-validation/additional-methods.js:630
 630     regex = new RegExp( regex );


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add d34a406e39b290ba655af18cba422ec3_2
File: public/plugins/jquery-validation/additional-methods.js:686
 686    return this.optional( element ) || value.match( new RegExp( "\\.(" + param + ")$", "i" ) );


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add d34a406e39b290ba655af18cba422ec3_3
File: public/plugins/jquery-validation/additional-methods.js:1163
 1163       param = new RegExp( "^(?:" + param + ")$" );


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add d35e2233225ea11e903372f4c0a6676d_0
File: public/plugins/jquery-validation/jquery.validate.js:265
 265        source = source.replace( new RegExp( "\\{" + i + "\\}", "g" ), function() {


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add 4e7d9bfa4c185263330e8a265cd8a473_0
File: public/plugins/jsgrid/jsgrid.js:1822
 1822                     param = new RegExp("^(?:" + param + ")$");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add c4022f9966f46901bcff6fc5f9b26900_0
File: public/plugins/plugins/ekko-lightbox/ekko-lightbox.js:498
 498                if (typeof match[2] === "string" && match[2].length > 0 && match[2].replace(new RegExp(':(' + ({
 499                    "http:": 80,
 500                    "https:": 443
 501                })[location.protocol] + ')?$'), "") !== location.host) return true;


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add 90bc9238d3500cf19516df6276c4375d_0
File: public/plugins/plugins/inputmask/inputmask/inputmask.date.extensions.js:83
 83             opts.tokenizer = new RegExp(opts.tokenizer, "g");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add ab600a6b771c5da9bacbe99f90dad1e4_0
File: public/plugins/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:197
 197                 processValue = processValue.replace(new RegExp(Inputmask.escapeRegex(opts.groupSeparator), "g"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add ab600a6b771c5da9bacbe99f90dad1e4_1
File: public/plugins/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:198
 198                 processValue = processValue.replace(new RegExp("[-" + Inputmask.escapeRegex(opts.negationSymbol.front) + "]", "g"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add ab600a6b771c5da9bacbe99f90dad1e4_2
File: public/plugins/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:199
 199                 processValue = processValue.replace(new RegExp(Inputmask.escapeRegex(opts.negationSymbol.back) + "$"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add ab600a6b771c5da9bacbe99f90dad1e4_3
File: public/plugins/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:201
 201                     processValue = processValue.replace(new RegExp(Inputmask.escapeRegex(opts.placeholder), "g"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add ab600a6b771c5da9bacbe99f90dad1e4_4
File: public/plugins/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:283
 283                             opts.min = opts.min.toString().replace(new RegExp(Inputmask.escapeRegex(opts.groupSeparator), "g"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add ab600a6b771c5da9bacbe99f90dad1e4_5
File: public/plugins/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:289
 289                             opts.max = opts.max.toString().replace(new RegExp(Inputmask.escapeRegex(opts.groupSeparator), "g"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add ab600a6b771c5da9bacbe99f90dad1e4_6
File: public/plugins/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:347
 347                     return emptyCheck ? new RegExp("[" + Inputmask.escapeRegex(opts.negationSymbol.front) + "+]?") : new RegExp("[" + Inputmask.escapeRegex(opts.negationSymbol.front) + "+]?\\d+");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add ab600a6b771c5da9bacbe99f90dad1e4_7
File: public/plugins/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:350
 350                     return new RegExp("[\\d" + Inputmask.escapeRegex(opts.groupSeparator) + Inputmask.escapeRegex(opts.placeholder.charAt(0)) + "]+");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add ab600a6b771c5da9bacbe99f90dad1e4_8
File: public/plugins/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:371
 371                         isValid = strict ? new RegExp("[0-9" + Inputmask.escapeRegex(opts.groupSeparator) + "]").test(chrs) : new RegExp("[0-9]").test(chrs);


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add ab600a6b771c5da9bacbe99f90dad1e4_9
File: public/plugins/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:375
 375                                 processValue = processValue.replace(new RegExp("[-" + Inputmask.escapeRegex(opts.negationSymbol.front) + "]", "g"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add ab600a6b771c5da9bacbe99f90dad1e4_10
File: public/plugins/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:376
 376                                 processValue = processValue.replace(new RegExp(Inputmask.escapeRegex(opts.negationSymbol.back) + "$"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add ab600a6b771c5da9bacbe99f90dad1e4_11
File: public/plugins/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:435
 435                         var isValid = new RegExp(radix).test(chrs);


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add ab600a6b771c5da9bacbe99f90dad1e4_12
File: public/plugins/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:455
 455                 processValue = processValue.replace(new RegExp(Inputmask.escapeRegex(opts.groupSeparator), "g"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add ab600a6b771c5da9bacbe99f90dad1e4_13
File: public/plugins/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:461
 461                     processValue = processValue.replace(new RegExp("^" + Inputmask.escapeRegex(opts.negationSymbol.front)), "-");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add ab600a6b771c5da9bacbe99f90dad1e4_14
File: public/plugins/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:462
 462                     processValue = processValue.replace(new RegExp(Inputmask.escapeRegex(opts.negationSymbol.back) + "$"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add ab600a6b771c5da9bacbe99f90dad1e4_15
File: public/plugins/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:469
 469                 maskedValue = maskedValue.replace(new RegExp("^" + Inputmask.escapeRegex(opts.negationSymbol.front)), "-");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add ab600a6b771c5da9bacbe99f90dad1e4_16
File: public/plugins/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:470
 470                 maskedValue = maskedValue.replace(new RegExp(Inputmask.escapeRegex(opts.negationSymbol.back) + "$"), "");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add ab600a6b771c5da9bacbe99f90dad1e4_17
File: public/plugins/plugins/inputmask/inputmask/inputmask.numeric.extensions.js:473
 473                 maskedValue = maskedValue.replace(new RegExp(Inputmask.escapeRegex(opts.groupSeparator) + "([0-9]{3})", "g"), "$1");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add 3472b89dafe5f0031037bc6e4e51397d_0
File: public/plugins/plugins/jquery-validation/additional-methods.js:103
 103            regex = new RegExp( ".?(" + typeParam + ")$", "i" );


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add 3472b89dafe5f0031037bc6e4e51397d_1
File: public/plugins/plugins/jquery-validation/additional-methods.js:630
 630     regex = new RegExp( regex );


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add 3472b89dafe5f0031037bc6e4e51397d_2
File: public/plugins/plugins/jquery-validation/additional-methods.js:686
 686    return this.optional( element ) || value.match( new RegExp( "\\.(" + param + ")$", "i" ) );


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add 3472b89dafe5f0031037bc6e4e51397d_3
File: public/plugins/plugins/jquery-validation/additional-methods.js:1163
 1163       param = new RegExp( "^(?:" + param + ")$" );


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add 28e32d09ee09638b97c88a314e66e3e8_0
File: public/plugins/plugins/jquery-validation/jquery.validate.js:265
 265        source = source.replace( new RegExp( "\\{" + i + "\\}", "g" ), function() {


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add 9b0e785d597da1afa3646a87ee1c4bfc_0
File: public/plugins/plugins/jsgrid/jsgrid.js:1822
 1822                     param = new RegExp("^(?:" + param + ")$");


MEDIUM: Unsanitized dynamic input in regular expression [CWE-1333]
https://docs.bearer.com/reference/rules/javascript_lang_dynamic_regex
To ignore this finding, run: bearer ignore add 6f8b264e2d292421efda5968d019adad_0
File: utils/utility.js:94
 94         let rgx = new RegExp('(public\\[\\d+\\] +.*' + search + '.*)');


MEDIUM: Observable Timing Discrepancy [CWE-208]
https://docs.bearer.com/reference/rules/javascript_lang_observable_timing
To ignore this finding, run: bearer ignore add 590eab88a7f4cf955e70094d4308dea6_0
File: public/plugins/moment/locale/ko.js:71
 71             return token === '오후';


MEDIUM: Observable Timing Discrepancy [CWE-208]
https://docs.bearer.com/reference/rules/javascript_lang_observable_timing
To ignore this finding, run: bearer ignore add d7ee8a2b62bc3d3d73ee02f298cb1e29_0
File: public/plugins/plugins/moment/locale/ko.js:71
 71             return token === '오후';


LOW: Usage of insufficient random value [CWE-330]
https://docs.bearer.com/reference/rules/javascript_lang_insufficiently_random_values
To ignore this finding, run: bearer ignore add 9ac6deab06f865421f42da4281a376b4_0
File: public/plugins/ekko-lightbox/ekko-lightbox.js:94
 94             this._modalId = 'ekkoLightbox-' + Math.floor(Math.random() * 1000 + 1);


LOW: Usage of insufficient random value [CWE-330]
https://docs.bearer.com/reference/rules/javascript_lang_insufficiently_random_values
To ignore this finding, run: bearer ignore add e58cdf499ece9923203abf70fbfcec37_0
File: public/plugins/jquery/core.js:200
 200    expando: "jQuery" + ( version + Math.random() ).replace( /\D/g, "" ),


LOW: Usage of insufficient random value [CWE-330]
https://docs.bearer.com/reference/rules/javascript_lang_insufficiently_random_values
To ignore this finding, run: bearer ignore add 5cf47d90cf3c4bf6003154d5f1386fd7_0
File: public/plugins/plugins/ekko-lightbox/ekko-lightbox.js:94
 94             this._modalId = 'ekkoLightbox-' + Math.floor(Math.random() * 1000 + 1);


LOW: Usage of insufficient random value [CWE-330]
https://docs.bearer.com/reference/rules/javascript_lang_insufficiently_random_values
To ignore this finding, run: bearer ignore add 463d64964145fe185e500a90ba6223cb_0
File: public/plugins/plugins/jquery/core.js:200
 200    expando: "jQuery" + ( version + Math.random() ).replace( /\D/g, "" ),


LOW: Usage of insufficient random value [CWE-330]
https://docs.bearer.com/reference/rules/javascript_lang_insufficiently_random_values
To ignore this finding, run: bearer ignore add 8ab86a08291458e649ca82e9da5de88a_0
File: public/plugins/plugins/raphael/dev/raphael.svg.js:669
 669             return ("0000" + (Math.random()*Math.pow(36,5) << 0).toString(36)).slice(-5);


LOW: Usage of insufficient random value [CWE-330]
https://docs.bearer.com/reference/rules/javascript_lang_insufficiently_random_values
To ignore this finding, run: bearer ignore add aa117b5507c4fa8334161826c67f8389_0
File: public/plugins/raphael/dev/raphael.svg.js:669
 669             return ("0000" + (Math.random()*Math.pow(36,5) << 0).toString(36)).slice(-5);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 5e4dea42595ca2ac86dd3eb02c1e3d2a_0
File: models/usersModel.js:32
 32                 console.log("error : " + err);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 5e4dea42595ca2ac86dd3eb02c1e3d2a_1
File: models/usersModel.js:46
 46                 console.log("error : " + err);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 5e4dea42595ca2ac86dd3eb02c1e3d2a_2
File: models/usersModel.js:59
 59                 console.log("error : " + err);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 5e4dea42595ca2ac86dd3eb02c1e3d2a_3
File: models/usersModel.js:73
 73                 console.log("error : " + err);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 7163c140812433d8b391087e439529a1_0
File: public/plugins/bootstrap-slider/bootstrap-slider.js:133
 133                console.error(message);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add da3cc6963cc7a0da64edd2eb90d1d8be_0
File: public/plugins/bootstrap4-duallistbox/jquery.bootstrap-duallistbox.js:112
 112     console.log(s, args);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add a04f5e906b509694d39bb3f9b8449d9b_0
File: public/plugins/ekko-lightbox/ekko-lightbox.js:508
 508                console.error(message);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 55c9ee0cd60732000a8b84cdb8d605f0_0
File: public/plugins/ion-rangeslider/js/ion.rangeSlider.js:340
 340             console && console.warn && console.warn("Base element should be <input>!", $inp[0]);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 11fce7bad4171d894f4dfb3a632ab8ac_0
File: public/plugins/jquery-validation/jquery.validate.js:655
 655                    console.error( "%o has no name assigned", this );


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 11fce7bad4171d894f4dfb3a632ab8ac_1
File: public/plugins/jquery-validation/jquery.validate.js:812
 812                        console.log( "Exception occurred when checking element " + element.id + ", check the '" + rule.method + "' method.", e );


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 22eac298e6b749e55f66d64440c45a05_0
File: public/plugins/pace-progress/pace.js:132
 132       return typeof console !== "undefined" && console !== null ? console.error("Error parsing inline pace options", e) : void 0;


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 0288d57adc34e53f376d50cd5b3c3fe4_0
File: public/plugins/plugins/bootstrap-slider/bootstrap-slider.js:133
 133                console.error(message);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 5d876ebffd80009d762ea019c0b23d53_0
File: public/plugins/plugins/bootstrap4-duallistbox/jquery.bootstrap-duallistbox.js:112
 112     console.log(s, args);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 083ae46c7b1793b134c5b73c39456b89_0
File: public/plugins/plugins/ekko-lightbox/ekko-lightbox.js:508
 508                console.error(message);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 7730a4891dd603d9e7156666b60ee39a_0
File: public/plugins/plugins/ion-rangeslider/js/ion.rangeSlider.js:340
 340             console && console.warn && console.warn("Base element should be <input>!", $inp[0]);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add a0c504a48e1ef7880c23c7c39fe194fd_0
File: public/plugins/plugins/jquery-validation/jquery.validate.js:655
 655                    console.error( "%o has no name assigned", this );


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add a0c504a48e1ef7880c23c7c39fe194fd_1
File: public/plugins/plugins/jquery-validation/jquery.validate.js:812
 812                        console.log( "Exception occurred when checking element " + element.id + ", check the '" + rule.method + "' method.", e );


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 90ba5230c88ef948258fd7799ed96e44_0
File: public/plugins/plugins/pace-progress/pace.js:132
 132       return typeof console !== "undefined" && console !== null ? console.error("Error parsing inline pace options", e) : void 0;


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 185bcf4aa08d92d3a5bd6d397f6b6800_0
File: public/plugins/plugins/popper/esm/popper-utils.js:922
 922     console.warn(requested + ' modifier is required by ' + _requesting + ' modifier in order to work, be sure to include it before ' + _requesting + '!');


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 1134a6e4ddd9fd0bfab7cef94d90764a_0
File: public/plugins/plugins/popper/esm/popper.js:1392
 1392     console.warn(requested + ' modifier is required by ' + _requesting + ' modifier in order to work, be sure to include it before ' + _requesting + '!');


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add fac34c4c0342be2ed7e4636c786c56b7_0
File: public/plugins/plugins/popper/umd/popper-utils.js:928
 928     console.warn(requested + ' modifier is required by ' + _requesting + ' modifier in order to work, be sure to include it before ' + _requesting + '!');


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 5d6c93bfc86f1a91ca333a47c9399f14_0
File: public/plugins/plugins/popper/umd/popper.js:1398
 1398     console.warn(requested + ' modifier is required by ' + _requesting + ' modifier in order to work, be sure to include it before ' + _requesting + '!');


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add f5d0296d7a08f08a97d5dec1472a5d38_0
File: public/plugins/popper/esm/popper-utils.js:922
 922     console.warn(requested + ' modifier is required by ' + _requesting + ' modifier in order to work, be sure to include it before ' + _requesting + '!');


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 18b8c8c54e8703f15d33e2a97e09cf40_0
File: public/plugins/popper/esm/popper.js:1392
 1392     console.warn(requested + ' modifier is required by ' + _requesting + ' modifier in order to work, be sure to include it before ' + _requesting + '!');


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 595eb6c2aad5dc34a3eee137dfb5346a_0
File: public/plugins/popper/umd/popper-utils.js:928
 928     console.warn(requested + ' modifier is required by ' + _requesting + ' modifier in order to work, be sure to include it before ' + _requesting + '!');


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 4b8c24ff1f9b235d05e9a183eb269f8e_0
File: public/plugins/popper/umd/popper.js:1398
 1398     console.warn(requested + ' modifier is required by ' + _requesting + ' modifier in order to work, be sure to include it before ' + _requesting + '!');


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 312b79100a30d9f55134e1d1fa385966_0
File: routes/users/user.js:58
 58                 console.log("err : " + err);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 312b79100a30d9f55134e1d1fa385966_1
File: routes/users/user.js:72
 72                 console.log("err : " + err);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 312b79100a30d9f55134e1d1fa385966_2
File: routes/users/user.js:83
 83                 console.log("err : " + err);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 312b79100a30d9f55134e1d1fa385966_3
File: routes/users/user.js:97
 97                 console.log("err : " + err);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 312b79100a30d9f55134e1d1fa385966_4
File: routes/users/user.js:111
 111                 console.log("err : " + err);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 312b79100a30d9f55134e1d1fa385966_5
File: routes/users/user.js:126
 126                 console.log("err : " + err);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add 312b79100a30d9f55134e1d1fa385966_6
File: routes/users/user.js:200
 200                 console.log("err : " + err);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add a200a9073fd927c46537934d2602069f_0
File: utils/utility.js:45
 45     console.log("isFromBlackListOfSqli : " + user_input);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add a200a9073fd927c46537934d2602069f_1
File: utils/utility.js:64
 64         console.log("command : " + command);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add a200a9073fd927c46537934d2602069f_2
File: utils/utility.js:107
 107                 console.log("from utils - resp : " + resp);


LOW: Leakage of information in logger message [CWE-532]
https://docs.bearer.com/reference/rules/javascript_lang_logger_leak
To ignore this finding, run: bearer ignore add a200a9073fd927c46537934d2602069f_3
File: utils/utility.js:110
 110                 console.log("from utils error - : " + err);

=====================================
```
__Container Scan__

```
Testing 047527637988.dkr.ecr.us-east-1.amazonaws.com/n5-vulnnodeapp:latest...

Organization:      xwindwolf
Package manager:   deb
Target file:       Dockerfile
Project name:      docker-image|047527637988.dkr.ecr.us-east-1.amazonaws.com/n5-vulnnodeapp
Docker image:      047527637988.dkr.ecr.us-east-1.amazonaws.com/n5-vulnnodeapp:latest
Platform:          linux/amd64
Base image:        ubuntu:latest
Licenses:          enabled

✔ Tested 141 dependencies for known issues, no vulnerable paths found.
Note that we currently do not have vulnerability information for Ubuntu 24.04, which we detected in your image.
-------------------------------------------------------

Testing 047527637988.dkr.ecr.us-east-1.amazonaws.com/n5-vulnnodeapp:latest...
Tested 13 dependencies for known issues, found 1 issue.
Issues with no direct upgrade or patch:
  ✗ Arbitrary Code Execution [Critical Severity][https://security.snyk.io/vuln/npm:node-serialize:20170208] in node-serialize@0.0.4
    introduced by node-serialize@0.0.4
  No upgrade or patch available

Organization:      xwindwolf
Package manager:   npm
Target file:       /opt/vuln-node-app/package.json
Project name:      reportcreator
Docker image:      047527637988.dkr.ecr.us-east-1.amazonaws.com/n5-vulnnodeapp:latest
Licenses:          enabled

Pro tip: use `--exclude-base-image-vulns` to exclude from display Docker base image vulnerabilities.
Snyk found some vulnerabilities in your image applications (Snyk searches for these vulnerabilities by default). See https://snyk.co/app-vulns for more information.
To remove these messages in the future, please run `snyk config set disableSuggestions=true`
-------------------------------------------------------

Testing 047527637988.dkr.ecr.us-east-1.amazonaws.com/n5-vulnnodeapp:latest...

Organization:      xwindwolf
Package manager:   gomodules
Target file:       /opt/vuln-node-app/bin/bearer
Project name:      github.com/bearer/bearer
Docker image:      047527637988.dkr.ecr.us-east-1.amazonaws.com/n5-vulnnodeapp:latest
Licenses:          enabled

✔ Tested 253 dependencies for known issues, no vulnerable paths found.

Tested 3 projects, 1 contained vulnerable paths.
```
