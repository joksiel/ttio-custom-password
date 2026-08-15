# ttio-custom-password
this is a tool i made to **change your [territorial.io](https://territorial.io/) account password to any >15 byte string.**
keep in mind that **the game forces 15 character long passwords, anything shorter will get padded with '-'s.**

everything in this script **can be recreated in territorial.io or a mod of territorial.io**, and **does not break the [territorial.io TOS](https://territorial.io/terms)** as modification to the existing account system "may be extended as necessary". necessary in this case would be QOL
# required
nodejs
# how it works
1. sends an init packet to validate websocket connection
2. receives and solves PoW challenge
3. sends account info to login
4. sends your new password
5. now, password = new password
