yubikey-server
==============

Run your own yubikey authentication server

* Create a mySQL database
* Copy all perl files to a CGI directory.
* Edit db.pl and adjust the database parameters to your selected database
* Install the Auth::Yubikey_Decrypter perl module
* Ensure register.pl and authenticate.pl perl scripts have chmod +x 

On the Yubikey
* Run the Yubikey personalization tool
* Create a new public ID, private ID, and AES Key.
* Write those to the Yubikey (NOTE ! This will break the YubiKey against the Yubico servers !!)
* Browse to http://yourserver/cgi-bin/register.pl 
* Enter the public ID, private ID, and AES key into the registration form.
* Once registered, you can authenticate through http://yourserver/cgi-bin/authenticate.pl

