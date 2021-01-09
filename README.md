# Solitude

Solitude is a privacy analysis tool that enables anyone to conduct their own privacy investigations. Whether a curious novice or a more advanced researcher, Solitude makes the process of evaluating user privacy within an app accessible for everyone.
## Install for Mac OS X

1. `git clone https://github.com/nccgroup/Solitude`
2. Install [Docker](https://docs.docker.com/docker-for-mac/install/)
3. `docker-compose -f docker-compose.prod.yml build`
4. `docker-compose -f docker-compse.prod.yml up`
5. Browse to http://localhost:5000 and follow the instructions to start the VPN server and configure your mobile device with a VPN profile and mitm proxy certificate.

#### Install locally (without docker-compose) on Mac OS X
1. Install [Docker](https://docs.docker.com/docker-for-mac/install/)
2. `brew install mysql`
3. Run the mysql docker container: (do this first before installing Solitude as it takes a minute for the container to start)
 
`docker run -p 3306:3306 -d  --name mysql -e MYSQL_ROOT_PASSWORD=solitude mysql` (change the default password here and see instructions below to change database configs)
   
4. `git clone https://github.com/nccgroup/Solitude`
5. `cd Solitude && python3 -m venv venv`
6. `source venv/bin/activate`
7. `pip3 install -r requirements.txt`
8. `python3 run.py`
9. Browse to http://localhost:5000 and configure browser to proxy all HTTP traffic through localhost:8080

## Install for Linux
1. Install [Docker](https://docs.docker.com/engine/install/ubuntu/) and [Docker-compose](https://docs.docker.com/compose/install/)
2. `docker-compose -f docker-compose.prod.yml build`
3. `docker-compose -f docker-compse.prod.yml up`
4. Browse to http://localhost:5000 and follow the instructions to start the VPN server and configure your mobile device with a VPN profile and mitm proxy certificate.

#### Install locally (without docker-compose) on Linux
1. Install [Docker](https://docs.docker.com/engine/install/ubuntu/)
2. Run the mysql docker container (do this first before installing Solitude as it takes a minute for the container to start)

`docker run -p 3306:3306 -d  --name mysql -e MYSQL_ROOT_PASSWORD=solitude mysql` (change the default password here and see instructions below to change database configs)

3. `git clone https://github.com/nccgroup/Solitude`
4. `cd Solitude && python3 -m venv venv`
5. `source venv/bin/activate`
6. `sudo apt-get install libmysqlclient-dev`
7. `pip3 install -r requirements.txt`
8. `python3 run.py`
9. Browse to http://localhost:5000 and configure browser to proxy all HTTP traffic through localhost:8080


## Database Config
To change the default database password. Edit the `.env` file to the password of your choosing. 

## Configure Solitude!
Configure any of the data you want traced in the `myrules.json` file. If a match is
found in any HTTP traffic being emitted from the web application or mobile app the configured data will be displayed in the web interface and the domain that the data with whom that data is being shared with.

    
#### How does Solitude work?
Solitude runs an OpenVPN server inside of a docker container which then fowards all HTTP traffic to 
a an HTTP interecpting proxy (mitmproxy) through a feature that makes use of the add-on API in mitmproxy. 


#### How does Solitude searching work?

Solitude makes use of Yara rules to search through all the HTTP traffic that you proxy through the tool. 
Yara rules while relatively easy to write can be tedious so solitude does some of the heavy lifting for you.
In the `myrules.json` file, define a key and value you pair of the type of data you would like to search for. There are some examples
provided in the `myrules.json` but feel free to add your own data. The key should be the type of data you are searching for such as "My phone number". 
This key is used for the output generated when a match is found. The value should be the exact data you would like to match. Take into account
different data formats so creating more entry for each piece of data might be necessary. For example a phone number or birthday might have multiple formats.
03-03-1991 or March, 3rd 1991. If you want to add new rules in the JSON file
Solitude will generate Yara rules for you each time you start the proxy.

Example: `"phoneNumber": "555-555-5555",
          "Address": "123 Sutter Street, San Francisco 94105"`


#### Solitude Features

    * base64 and url recursive decoding (requests that are encoded say base64>url>base64 can be decoded and searched through)
    * protobuf support (decodes the first layer of any protobuf request)
    * Searches for MD5, SHA1, SHA256 of all data defined in myrules.json
    * Built-in GPS, internal IP Address and Mac Address regular expression searches

### Acknowledgements

* Decoders modified from Phorcys recursive decoders: https://github.com/PiRanhaLysis/Phorcys
* Protobuf from BlackBoxProtobuf Thanks Ryan! : https://github.com/nccgroup/blackboxprotobuf
* Theme from Start Bootstrap - SB Admin: https://github.com/startbootstrap/startbootstrap-sb-admin
* VPN Config scripts from Sid Adukia. Thanks Sid! 

