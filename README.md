# EdDSA Playground

## Generate the key for testing

```shell
ssh-keygen -o -a 100 -t ed25519 -f ./src/main/resources/id_ed25519 -C "john.doe@example.org"
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
