# importing Libraries
from flask import Flask, render_template, url_for, request, redirect, flash
from flask import jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# importing database
from catalog_setup import Base, Category, Item, Description, User

# importing required libraries and classes
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
app = Flask(__name__)
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "category"

# creating a session to access database
engine = create_engine('sqlite:///catalog_final_users.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# function for logging into Google plus and displaying sign in buttoon


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


# function for connecting to google plus
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# To disconnect google plus account


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('current user not connected '), 401)
        response.headers['Content-type'] = 'application/json'
        return response
    access_token = login_session['access_token']
    print login_session.get('access_token')
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('disconnected'), 200)
        response.headers['Content-Type'] = 'application/json'
        return (redirect(url_for('categories')))
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# to add new items into database.
@app.route('/categories/new/', methods=['GET', 'POST'])
def addItem():
    if 'username' not in login_session:
        return redirect('/login')
    if(request.method == 'POST'):
        category = Category(name=request.form['category_name'],
                            user_id=login_session.get('user_id'))
        session.add(category)
        session.commit()
        newItem = Item(name=request.form['name'],
                       category=category, user_id=login_session.get('user_id'))
        session.add(newItem)
        session.commit()
        description = Description(
            description=request.form['description'], item=newItem)
        session.add(description)
        session.commit()
        return redirect(url_for('categories'))
    else:
        return render_template('newitem.html')


# To display categories to user
@app.route('/')
@app.route('/categories/')
def categories():
    if 'username' not in login_session:
        categories = session.query(Category).all()
        return render_template('index.html', categories=categories)
    else:
        categories = session.query(Category).all()
        return render_template('user.html', categories=categories)


# To display items in specific category
@app.route('/categories/<int:category_id>/')
def Items(category_id):
    item = session.query(Item).filter_by(category_id=category_id).all()
    return render_template('main.html', items=item)


# To display descriptiion of specific item
@app.route('/categories/<int:category_id>/<int:item_id>/')
def description(category_id, item_id):
    desc = session.query(Description).filter_by(item_id=item_id)
    return render_template('desc.html', desc=desc)


# To edit a specific item in a category
@app.route('/categories/<int:item_id>/<int:id>edit', methods=['GET', 'POST'])
def editItem(item_id, id):
    if 'username' not in login_session:
        return redirect('/login')

    showitems = session.query(Item).filter_by(id=item_id).one()
    creator = getUserInfo(showitems.user_id)

    if creator.id != login_session['user_id']:
        output = ''
        output += '<h1> you cannot edit this item</h1>'
        return output
    if(request.method == 'POST'):
        changenewItem = session.query(Item).filter_by(id=item_id).one()
        changenewItem.name = request.form['name']
        session.add(changenewItem)
        session.commit()
        changedescription = session.query(Description).filter_by(id=id).one()
        changedescription.description = request.form['description']
        session.add(changedescription)
        session.commit()
        return redirect(url_for('categories'))
    else:
        return render_template('edititem.html', item_id=item_id, id=id)

# API end point


@app.route('/categories/JSON')
def catalogJSON():
    categories = session.query(Category).all()
    return jsonify(categories=[r.serialize for r in categories])


@app.route('/categories/items/JSON')
def catalogitemsJSON():
    items = session.query(Item).all()
    return jsonify(items=[r.serialize for r in items])


@app.route('/categories/items/description/JSON')
def catalogitemsdescriptionJSON():
    description = session.query(Description).all()
    return jsonify(description=[r.serialize for r in description])


# to delete a category after login
@app.route('/categories/<int:category_id>/delete', methods=['GET', 'POST'])
def delItem(category_id):
    showCategories = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(showCategories.user_id)

    if creator.id != login_session['user_id']:
        output = ''
        output += '<h1> you cannot delete this </h1>'
        return output

    categoryToDelete = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        session.delete(categoryToDelete)
        session.commit()
        return redirect('categories')
    else:
        return render_template('delitem.html', categories=categories)

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
