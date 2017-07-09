------------------------------------------------------------Project description----------------------------------------------------------

Simple catalog web application designed using python.

THE FOLLOWING COMPONENTS NEEDED TO RUN THE SUCCESSFULLY APPLICATION.

1)PYTHON - install from https://www.python.org/ 

2)SQL alchemy install from https://www.sqlalchemy.org/

3)FLASK install from http://flask.pocoo.org/ 



----RUNNING THE APPLICATION-------------

1)Run the catalog_setup.py file  in vagrant using following command python filename.py in order to load the tables in a database.

2)Run catalog.py to start the  server.

3)open the webbrowser and go to following the following URL "http://localhost:5000

4)login to add, edit or delete items using Google plus sign.

5) logout and login as other user to check that items added by other user cannot be edited. 


when not  logged in user can only see the categories and items and their description.

when logged in user can add new items and also can edit items and also delete the items.

End points

url '/categories/JSON' - for categories.

url '/categories/items/JSON'- for items.

url '/categories/items/description/JSON' - for descriptions about items. 