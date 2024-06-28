# Secure Chat Room

## Installation

L'installation est simple. Il suffit de télécharger le dépôt et de lancer un serveur ainsi qu'un ou plusieurs clients pour démarrer la communication ou l'échange de fichiers (notez que l'échange de fichiers n'est pas encore pris en charge).

Commande pour lancer le serveur, aucun fichier externe n'est nécessaire.

```bash
python .\InfinityLockServer.py --generate-default-cert
```

Et du côté client:

```bash
python .\InfinityLockClient.py --email [email (ici juste un pseudo)] --allow-invalid-cert
```

Pour obtenir des spécifications plus détaillées, vous pouvez exécuter la commande `-h` sur les deux exécutables pour découvrir rapidement les différentes configurations possibles.

## Matériel(s) nécessaire(s) et configuration

Dans le cadre de notre projet ou appel d'offres, il n'est pas nécessaire de brancher, configurer ou installer du matériel spécifique. Cependant, il est possible de modifier les configurations par défaut (par exemple, utiliser ses propres certificats, changer l'interface et le port d'écoute, autoriser les certificats invalides, etc.). Il suffit d'avoir une machine capable d'exécuter Python et d'installer les extensions mentionnées dans les fichiers `requirements.txt`.

```bash
pip install -r serverRequirements.txt (ou clientRequirements.txt)
```

## Scripts pour créer et/ou alimenter la base de données

Aucun script spécifique n'est requis pour créer ou alimenter la base de données, à moins que l'on considère Python comme un langage de script. Tout est créé et géré directement dans les différents exécutables pour rendre l'utilisation aussi simple et intuitive que possible.

## Identifiants pour se connecter (le cas échéant)

Pour le moment, il suffit d'entrer un pseudonyme pour "créer son compte". À terme, nous envisageons que l'enregistrement se fasse via un email (d'où le nom de l'argument). Une fois l'enregistrement effectué, un jeu de clés RSA est créé côté client. La clé publique est envoyée au serveur, permettant ainsi à tout le monde d'envoyer des messages au client sans que ceux-ci ne soient lisibles par le serveur.

Pour simplifier, je vous invite à consulter le diagramme de séquence :

- Si le fichier contenant le jeu de clés est absent sur le client, alors celui-ci est considéré comme non enregistré.

```mermaid
sequenceDiagram
    participant Utilisateur
    participant Client
    participant Serveur

    Note over Utilisateur, Serveur: Création d'un échange sécurisé avec le ssl/tls
    Note over Utilisateur, Serveur: Enregistrement d'un utilisateur

    Utilisateur->>Client: Demande d'enregistrement avec email (pseudo)
    Client->>Serveur: Demande d'enregistrement avec email (pseudo)
    Serveur->>Client: Demande de création d'un jeu de clés RSA
    Client->>Client: Génère le jeu de clés RSA
    Client->>Serveur: Envoie la clé publique
    Serveur->>Serveur: Enregistre la clé publique
    Serveur->>Client: Demande si le client veut activer le 2FA
    Client->>Utilisateur: Demande si l'utilisateur veut activer le 2FA
    Utilisateur->>Client: Donne son choix
    Client->>Serveur: Transmet le choix de l'utilisateur
    alt Si 2FA est oui
        Serveur->>Serveur: Génère le secret 2FA
        Serveur->>Client: Transmet le secret 2FA
        Client->>Utilisateur: Affiche le secret 2FA
        Utilisateur->>Utilisateur: Enregistre le secret sur son application
        Utilisateur->>Client: Donne le code à 6 chiffres généré
        Client->>Serveur: Transmet le code à 6 chiffres
        Serveur->>Serveur: Vérifie si la réponse est valide
    end
    Serveur->>Client: Valide l'enregistrement
    Client->>Utilisateur: Informe de la validation de l'enregistrement
```

- Dans le cas contraire, celui-ci considére qu'il est enregister

```mermaid
sequenceDiagram
    participant Utilisateur
    participant Client
    participant Serveur

    Note over Utilisateur, Serveur: Création d'un échange sécurisé avec le ssl/tls
    Note over Utilisateur, Serveur: Connexion d'un utilisateur

    Client->>Serveur: Demande d'authentification via signature RSA
    Serveur->>Client: Envoie une chaîne de 32 octets aléatoire à signer
    Client->>Client: Signe à l'aide de sa clé privée
    Client->>Serveur: Envoie le résultat signé
    Serveur->>Serveur: Vérifie à l'aide de la clé publique de l'email renseigné
    alt Si un secret 2FA est associé à l'email
        Serveur->>Client: Demande le code à 6 chiffres généré par le secret 2FA
        Client->>Utilisateur: Demande le code à 6 chiffres
        Utilisateur->>Client: Retransmet le code saisi
        Client->>Serveur: Retransmet le code saisi
        Serveur->>Serveur: Vérifie le code 2FA
    end
    Serveur->>Client: Authentification réussie
    Client->>Serveur: Envoie une demande de synchronisation avec le timestamp du dernier échange
    loop Jusqu'à ce que tous les messages soient envoyés
        Serveur->>Client: Envoie un message depuis l'intervalle
    end
```

Après l'authentification réussie, le processus de synchronisation des messages commence. Le client envoie une demande au serveur pour récupérer tous les messages qu'il n'a pas encore reçus. Cette étape est cruciale pour garantir que l'utilisateur a accès à tous les messages manquants depuis sa dernière connexion. À l'avenir, il est envisagé d'améliorer ce système de synchronisation en intégrant le statut des messages, tels que "lu", "distribué" et "envoyé". Cela permettra une gestion plus fine des interactions et assurera que les utilisateurs aient une vue complète de l'état de leurs communications.

## Activation de services sur une plateforme Cloud

Aucun service spécifique n'est requis pour être activé. Il est essentiel de s'assurer que le serveur soit accessible depuis l'extérieur. Côté client, il est crucial de fournir les arguments appropriés lors du lancement pour établir la connexion avec le serveur, y compris l'adresse IP et le port.

Pour tester rapidement le service, vous pouvez lancer le serveur avec :

```bash
python .\InfinityLockServer.py --generate-default-cert
```

Et pour lancer 1 ou plussieurs client

```bash
python .\InfinityLockClient.py --email [email] --allow-invalid-cert
```

Il suffit d'après de montrer les différent aspect à l'aide de l'interface.
