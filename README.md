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

if you get error 4211 try to update the build number field, which i commented next to, look for a function in the games code (where "this.du" is build number):
```
    function dL() {
      this.du = 1758;
      var dv = 2;
      var dw = 16;
      var dx = 33;
      this.rVersion = 25;
      this.dy = 0;
      this.di = function () {
        this.dz = 2;
        var e0 = '';
        this.o = dv + '.' + dw + '.' + dx;
        this.e1 = '12 Aug 2026 [' + this.o + e0 + ']';
        var e2 = window.location.hostname.toLowerCase();
        this.aA = e2.indexOf(S[23]) >= 0;
        this.e3 = e2.indexOf('github.io') >= 0;
        this.e4 = e2.indexOf(S[54]) >= 0;
        this.aB = e5();
        this.e6 = (new Date()).getTime() % 1048576;
      };
      this.n = 0;
      function e5() {
        try {
          return window.self !== window.top;
        } catch (e) {
          return true;
        }
      }
    }```
