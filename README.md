# EdDSA Playground

## Generate the key for testing

```shell
# ssh-keygen -t ed25519 -f ./src/main/resources/id_ed25519 -C "john.doe@example.org"

openssl genpkey -algorithm ed25519 -outform pem -out ./src/main/resources/private.pem 
openssl pkey -inform pem        -in ./src/main/resources/private.pem -pubout -out ./src/main/resources/public.pem

openssl pkey -inform pem        -in ./src/main/resources/private.pem -noout -text
openssl pkey -inform pem -pubin -in ./src/main/resources/public.pem  -noout -text
```

## Commands to build and run the application

### Package

```sh
mvn clean package
```

### Run the application

```sh
mvn exec:java
```
