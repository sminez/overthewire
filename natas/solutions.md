Natas
-----

### lvl-0
Just log in and view source. The password is in a comment:
gtVrDuiDfck831PqWsLEZy5gyDz1clto

### lvl-1
Same again but right click is disabled on the main page.
ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi

### lvl-2
There is a single pixel file present in the page. Truncate the url to get a
[directory listing](http://natas2.natas.labs.overthewire.org/files/) form where
you can get to users.txt:
```
# username:password
alice:BYNdCesZqW
bob:jw2ueICLvT
charlie:G5vCxkVV3m
natas3:sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14
eve:zo4mJWyNj2
mallory:9urtcpzBmH
```

### lvl-3
This time there is a comment saying:
```html
<!-- No more information leaks!! Not even Google will find it this time... -->
```
So, going to http://natas3.natas.labs.overthewire.org/robots.txt gives us the
following:
```
User-agent: *
Disallow: /s3cr3t/
```
This leads us to an [open directory](http://natas3.natas.labs.overthewire.org/s3cr3t/)
containing another users.txt file:
```
natas4:Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ
```
