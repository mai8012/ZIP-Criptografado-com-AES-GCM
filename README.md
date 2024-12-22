Um projeto em Go que implementa um sistema de compactação de arquivos com criptografia interna baseada em AES-GCM, utilizando chaves derivadas de senhas (PBKDF2 com SHA-256).

Observação Importante
O ZIP resultante não será compatível com ferramentas padrão como WinRAR, 7-Zip ou o unzip do Linux/Windows,
pois cada entry (arquivo interno) está criptografada manualmente.
Somente este programa (que conhece a rotina de encriptação/decriptação) conseguirá abrir o conteúdo.
O PBKDF2 está configurado com um salt fixo (para fins de demonstração). 
Em produção, é recomendável usar um salt aleatório e armazená-lo junto do arquivo 
(por exemplo, no cabeçalho), para que cada arquivo/usuário tenha seu salt próprio.
Se o usuário insistir em “unzip” para um arquivo que não seja um ZIP válido, 
o Go retornará “zip: not a valid zip file”.

🚀 Por que isso é útil?
Este código permite:
1️⃣ Criptografar cada arquivo individualmente dentro de um ZIP, garantindo que mesmo se o ZIP for comprometido, os arquivos individuais permanecem protegidos.
2️⃣ Segurança ajustável: com parâmetros de iterações no PBKDF2, é possível balancear entre performance e robustez contra ataques de força bruta.
3️⃣ Simplicidade: oferece uma interface básica de CLI para compactar ou descompactar com descriptografia automática.

💡 Casos de uso:

Armazenamento seguro de backups.
Transferência segura de arquivos sensíveis.
Exemplos didáticos para quem quer aprender Go e segurança da informação.
