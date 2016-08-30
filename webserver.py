from flask import Flask, render_template, url_for, request, redirect, flash, jsonify
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from database_setup import Base, Category, CategoryItem, User
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import httplib2
import json
from flask import make_response
import requests

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog App"

app = Flask(__name__)

# Create session and connect to DB ##


engine = create_engine('sqlite:///catalogapp.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Creates a state token to prevent forgery
# Save it in the session for later use


@app.route('/')
# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


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
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

    # DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session[
        'access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:

        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

# JSON serialize all Categories in DB


@app.route('/categories/JSON')
def allCategoriesJSON():
    """Queries and shows all Categories and their information stored in the DB. JSON endpoint data. 

    Args:
        no arguments
        
    Returns:
        jsonify: html page showing Categories information.
    """
    allcategories = session.query(Category).all()
    return jsonify(Category=[i.serialize for i in allcategories])

# JSON to serialize category items


@app.route('/categories/<int:category_id>/JSON')
def categoryItemsJSON(category_id):
    """Queries and shows all Items in a Category and their information stored in the DB. JSON endpoint data. 

    Args:
        category_id: the ID assigned to a Category in the app's DB.
        
    Returns:
        jsonify: html page showing Category's Items information.
    """
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(CategoryItem).filter_by(category_id=category_id)
    return jsonify(CategoryItems=[i.serialize for i in items])


# JSON to get one specific one category item API Endpoint Here


@app.route('/items/<int:id>/JSON')
def specificItemJSON(id):
    """Queries and shows specific Category's information stored in the DB. JSON endpoint data. 

    Args:
        id: the ID assigned to an Item in the app DB.
        
    Returns:
        jsonify: html page showing Category information.
    """
    item = session.query(CategoryItem).filter_by(id=id).first()
    return jsonify(item=item.id)

# Shows all Categories in DB


@app.route('/categories/')
def allCategories():
    """Queries and shows all Categories stored in the DB.

    Args:
        no arguments
        
    Returns:
        render_template(): html page showing all Category information and link to view the Category details.
    """
    allcategories = session.query(Category).all()
    if 'username' not in login_session:
        return render_template(
            'publiccategories.html',
            allcategories=allcategories)
    else:
        return render_template('categories.html', allcategories=allcategories)

# This page Shows all Items


@app.route('/items/')
def allItems():
    """Queries and shows all Items stored in the DB.

    Args:
        no arguments
        
    Returns:
        render_template(): html page showing all item information and link to view the items details.
    """
    allItems = session.query(CategoryItem).all()
    return render_template('items.html', allItems=allItems)

# This page shows specific Item


@app.route('/items/<int:id>/')
def specificItem(id):
    """Queries and shows specific Item stored in the DB. Checks and only allows logged in users and the Creator of item to delete or edit the item.

    Args:
        id: Item ID number stored in the DB.
        
    Returns:
        render_template(): html page showing item information and link to edit or delete item depending on users log in session.
    """
    item = session.query(CategoryItem).filter_by(id=id).first()
    creator = item.user.id
    if 'username' not in login_session:
        return render_template('publicitem.html', item=item)
    if 'username' in login_session and creator == login_session['user_id']:
        return render_template('item.html', item=item)
    else:
        return render_template('publicitem.html', item=item)

# This will show all Items in category


@app.route('/categories/<int:category_id>/')
def categoryItems(category_id):
    """Queries and shows all items in a specifc Category. Checks and only allows logged in users to add new items to the Category. 
       Checks if user is Creator of Category and allows that user to delete the entire Category

    Args:
        category_id: Category ID in DB to view all the items in. 
        
    Returns:
        render_template(): html page listing all items in the DB and delete or add new items.
    """
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(CategoryItem).filter_by(category_id=category_id)
    creator = category.user.id
    if 'username' not in login_session:
        return render_template(
            'publiccategory.html',
            category=category,
            items=items)
    if 'username' in login_session and creator == login_session['user_id']:
        return render_template('category.html', category=category, items=items)
    else:
        return render_template(
            'noncreatorcategory.html',
            category=category,
            items=items)

# New CategoryItem Function


@app.route('/categories/<int:category_id>/new/', methods=['GET', 'POST'])
def newCategoryItem(category_id):
    """Adds a new Item to a specifc Category. Only logged in user can add to a Category.

    Args:
        category_id: Category ID in DB to add the item to. 
        
    Returns:
        render_template(): html page with a form to add the item in the DB.
    """
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newItem = CategoryItem(
            name=request.form['name'],
            description=request.form['description'],
            category_id=category_id,
            user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash('New Item Succesfully Added!')
        return redirect(url_for('categoryItems', category_id=category_id))
    else:
        return render_template('newcategoryitem.html', category_id=category_id)

# Edit Category Item Name


@app.route(
    '/categories/<int:category_id>/<int:categoryitem_id>/edit/',
    methods=[
        'GET',
        'POST'])
def editCategoryItem(category_id, categoryitem_id):
    """Filters and edits a specific Item. Checks for logged in user and if the user created the item.
       Only creators of items can edit and delete their items.

    Args:
        category_id: The Category ID the item belongs to
        categoryitem_id: The Item ID assigned to the Item in the DB.
        
    Returns:
        render_template(): html page with a form to edit the item in the DB.
    """
    editedItem = session.query(CategoryItem).filter_by(
        id=categoryitem_id).one()
    creator = editedItem.user.id
    if 'username' not in login_session:
        return redirect('/login')
    if creator == login_session['user_id']:
        if request.method == 'POST':
            if request.form['name']:
                editedItem.name = request.form['name']
            if request.form['description']:
                editedItem.description = request.form['description']
            session.add(editedItem)
            session.commit()
            flash("Item has been edited!")
            return redirect(url_for('categoryItems', category_id=category_id))
        else:
            return render_template(
                'editcategoryitem.html',
                category_id=category_id,
                categoryitem_id=categoryitem_id,
                item=editedItem)

# Delete Item Route


@app.route(
    '/categories/<int:category_id>/<int:categoryitem_id>/delete/',
    methods=[
        'GET',
        'POST'])
def deleteCategoryItem(category_id, categoryitem_id):
    """Filters and deletes a specific Item from the Category. Checks for logged in user and if the user created the item.
       Only creators of items can edit and delete their items.

    Args:
        category_id: The Category ID the item belongs to
        categoryitem_id: The Item ID assigned to the Item in the DB.
        
    Returns:
        render_template(): html page with a warning message to delete the item from the DB.
    """
    itemToDelete = session.query(
        CategoryItem).filter_by(id=categoryitem_id).one()
    creator = itemToDelete.user.id
    if 'username' not in login_session:
        return redirect('/login')
    if creator == login_session['user_id']:
        if request.method == 'POST':
            session.delete(itemToDelete)
            session.commit()
            flash("Item was deleted!")
            return redirect(url_for('categoryItems', category_id=category_id))
        else:
            return render_template(
                'deletecategoryitem.html',
                item=itemToDelete)

# New Category Function


@app.route('/categories/new/', methods=['GET', 'POST'])
def newCategory():
    """Creates a new Category and adds it to the DB. Checks for and only allows logged in users.

    Args:
        no arguments
        
    Returns:
        render_template(): html page with forms to add category name to DB.
    """
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newCategory = Category(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newCategory)
        session.commit()
        flash('Succesfully Added New Category!')
        return redirect(url_for('allCategories'))
    else:
        return render_template('newcategory.html')

# Delete Category Route


@app.route('/categories/<int:id>/delete/', methods=['GET', 'POST'])
def deleteCategory(id):
    """Deletes the desired Category from the application. Only allows logged in creators of the Category to delete their own data. 

    Args:
        id: Primary Key ID assigned to the Category in the DB. 
        
    Returns:
        redirect(): redirects user to All Categories View if successfully deleted.
    """
    categoryDelete = session.query(Category).filter_by(id=id).one()
    itemsToDelete = session.query(CategoryItem).filter_by(category_id=id).all()
    creator = categoryDelete.user.id
    if 'username' not in login_session:
        return redirect('/login')
    if creator == login_session['user_id']:
        if request.method == 'POST':
            for item in itemsToDelete:
                session.delete(item)
            session.delete(categoryDelete)
            session.commit()
            flash("Category was deleted!")
            return redirect('/categories/')
        else:
            return render_template('deletecategory.html', item=categoryDelete)
    else:
        return redirect('/categories/')

# adds user to database


def createUser(login_session):
    """Takes the current login_session and stores the user into the APP DB for record keeping.

    Args:
        login_session: name email and picture of user's google info
        
    Returns:
        user.id: the ID assigned to the new user
    """
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

# gets the users information


def getUserInfo(user_id):
    """Takes the current sessions user email and storer users info from Google profile.

    Args:
        user_id: user's email address used with Google Log In
        
    Returns:
        user: an iterable list of the user's email picture and name
    """
    user = session.query(User).filter_by(id=user_id).one()
    return user

# get the user ID according to email


def getUserID(email):
    """Takes the current sessions user email and finds user ID in DB.

    Args:
        email: user's email address used with Google Log In
        
    Returns:
        id: the user's assigned ID in the Application DB
    """
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
