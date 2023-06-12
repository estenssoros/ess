# Estenssoro Secret Sharing


## Getting Started

#### create a key pair set

```bash
ssh-keygen
```

follow all prompts


#### install ess

```bash
go install ess
```

## Encrypting a file

```bash
ess encrypt -i <input file> -o <output file> -k <public key>
```

note: the public key is the one that ends in .pub (e.g. ~/.ssh/id_rsa.pub)

## Decrypting a file

```bash
ess decrypt -i <input file> -o <output file> -k <private key>
```

note: the private key is the one that does not have an extension (e.g. ~/.ssh/id_rsa)