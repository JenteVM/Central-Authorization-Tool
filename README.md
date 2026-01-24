# Central Authorization Tool

This project is to serve as a basic authorization tool
## Quick rundown

This project is made by JenteVM. It serves as a central point to authenticate and is just here for me to learn some things. It is made so other applications can just contact this application instead of all having different database to authenticate. Just makes it easier for if I make more projects which share the same users.

## Why you should or shouldn't use it

I would recommend this application to anyone who doesn't care about frequent updates but who does want something with basic security features and a central database (optional). I will warn you however that there may be some major bugs and support isn't present much as I am (and want to keep it) a one man team. 

## How to set it up (frontend)

*Read the wiki for detailed documentation.* <br><br>
Currently the frontend is only set up for my example, please do not use this but use your own.
My frontend is visible at https://jvm-authorization-tool.vercel.app/ and the back end at https://auth.jvm.hackclub.app/api/registry/ (Currently offline)

* __base_url/api/registry/__ 
  * allows you to get all registries or post a new one (if authorized in the .env)
* __base_url/api/registry/__*db_id*__/__ 
  * allows you to get a specific registry by id
* __base_url/api/registry/authenticate/__*db_id*__/__*token*__/__ 
  * allows you to authenticate a new origin for a registry via a generated token (use get request)
* __base_url/api/registry/authenticate/__*db_id*__/create/__ 
  * allows you to create a new token for use with the previous point (use get request; need to be authorized to do so; have post level auth for that database)
* __base_url/api/__*db_id*__/users/__ 
  * allows you to get all users (if authorized in the .env or database) or post a new one (if authorized in the database)
* __base_url/api/__*db_id*__/users/__*id_method*__/__*identifier*__/__ 
  * allows you to get a specific user by either id (id_method=id), username (id_method=username) or email (id_method=email)
* __base_url/api/__*db_id*__/users/authenticate/__*int:time_extension*__/__*token*__/__ 
  * allows you to authenticate a user with a token (token gets refreshed upon doing so), this needs to be done with a post request
* __base_url/api/__*db_id*__/users/authenticate/__*int:time_extension*__/0/__ 
  * allows you to authenticate a user with username and password (token is generated upon succesfull log in), this needs to be done with a post request
 
## Notice:
In my transition to the module approach for readability I did use AI assisted coding, I try and keep everything made by me so I do not think it is noticable much but this serves as a notice to anyone who is against the use of AI.

## Public Test
The frontend is available for testing at https://jvm-authorization-tool.vercel.app/, it ofcourse has some flaws, please do not mind those. The backend (for as far as is allowed) is visible at https://auth.jvm.hackclub.app/api/registry/ (it does not have an index). <br> The base user login info can be found on the testing page <br>

I ask of you to not try and use this user for anything else than to create your own database or to test. I do not want any changes made to this user, other users are fine, but changing this user would make the experience non-existent for others wanting to test it out which I would not want to happen.