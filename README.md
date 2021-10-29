### API_REST_JWT
Creación de una API con JWT

La persona debe loguearse para poder tener la información que requiere de los usuarios, abajo tenemos dos de los usuarios, un usuario admin y otro que no lo es, el primero tiene acceso a toda la información, puede agregar usuarios, consultar, promover y eliminar, mientras que el segundo no.

Usuarios actuales en la base de datos:

    User:
    {"name": "Juan", "password": "67890"} user
    {"name": "Rafa", "password": "12345"} manager
    {
        "users": [
            {
                "admin": true,
                "name": "Rafa",
                "password": "sha256$cywMKtPq0yMD4Iz6$5dfa9c4b499dd0c2521b74f3984127ab23559a03b46eba61d1644ec3d95803dd",
                "public_id": "a681c4b8-41a3-406c-bdec-b756dd8b56a5"
            },
            {
                "admin": false,
                "name": "Juan",
                "password": "sha256$XVYb3yKiuhxE5lJI$4e36c1219372528161d25aa09f5f754d5b49612b8472f8971328093b399e2e8b",
                "public_id": "80b84d83-e7bf-48cb-ad92-5fbc11f0d416"
            },
            {
                "admin": false,
                "name": "Derwin",
                "password": "sha256$byFtnr4HpuWS5iXx$f74fddca7c5b9e215d09cb75308f3716aecb2f94207ec2bdfe51c026e7522b5b",
                "public_id": "93ec50a1-277f-4229-a300-664282897af4"
            },
            {
                "admin": false,
                "name": "Laura",
                "password": "sha256$jyoGlL92Ce5B3Bz7$58968dde61b89f5c5efc172d49d175c4b1adb5fc7e14627202873f0244fdf008",
                "public_id": "8088f5cb-8181-446f-9b55-9f112487f203"
            },
            {
                "admin": false,
                "name": "Diana",
                "password": "sha256$IucZ90SQ7tyrKHVw$05b46b103fa49d0400f426fbb85d0c94aadbf5700e7a31bb38027f3716b6c172",
                "public_id": "0cef0e9f-d5da-460e-bccd-d71af83cbc3e"
            }
        ]
    }
