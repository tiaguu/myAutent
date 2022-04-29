Para executar o programa deve abrir o terminal e ir para dentro da diretoria onde o programa está contido. ( ex: SI/proj1 );

// Os ficheiros do cliente devem ser colocados numa pasta files no bin do projeto

Para iniciar o servidor deve usar o comando:
$ java -Djava.security.manager -Djava.security.policy=server.policy -cp "bin:lib/*" myAutent

Para utilizar o cliente podem ser utilizados alguns comandos:

Criar um utilizador
$ java -Djava.security.manager -Djava.security.policy=client.policy -cp bin myAutentClient -u 1 -a 127.0.0.1:23456 -p 123 -c 2 grupo025 pwd

Listar ficheiros
$ java -Djava.security.manager -Djava.security.policy=client.policy -cp bin myAutentClient -u 1 -a 127.0.0.1:23456 -p 123 -l

Enviar ficheiros
$ java -Djava.security.manager -Djava.security.policy=client.policy -cp bin myAutentClient -u 1 -a 127.0.0.1:23456 -p 123 -e file1.txt file2.txt

Pedir ficheiros
$ java -Djava.security.manager -Djava.security.policy=client.policy -cp bin myAutentClient -u 1 -a 127.0.0.1:23456 -p 123 -d file1.txt file2.txt

Enviar a síntese e receber a assinatura digital
$ java -Djava.security.manager -Djava.security.policy=client.policy -cp bin myAutentClient -u 1 -a 127.0.0.1:23456 -p 123 -s file1.txt file2.txt

Verificar a assinatura digital
$ java -Djava.security.manager -Djava.security.policy=client.policy -cp bin myAutentClient -u 1 -a 127.0.0.1:23456 -p 123 -v file1.txt file2.txt

No caso de não ser indicada uma password na linha de comando, esta será pedida posteriormente. 