import datetime
import functools
import os
import re
import urllib

from flask import (Flask, flash, Markup, redirect, render_template, request,
                   Response, session, url_for)
from markdown import markdown
from markdown.extensions.codehilite import CodeHiliteExtension
from markdown.extensions.extra import ExtraExtension
from micawber import bootstrap_basic, parse_html
from micawber.cache import Cache as OEmbedCache
from peewee import *
from playhouse.flask_utils import FlaskDB, get_object_or_404, object_list
from playhouse.sqlite_ext import *

# Blog configuration values.

#TODO: change this to 1-way hash procedure?
ADMIN_PASSWORD = 'ThisIsMyPassword'
APP_DIR = os.path.dirname(os.path.realpath(__file__))

#File Upload
UPLOAD_FOLDER = 'tmp'
ALLOWED_EXTENSIONS = set(['md']) #allows markdown only


# The playhouse.flask_utils.FlaskDB object accepts database URL configuration.
DATABASE = 'sqliteext:///%s' % os.path.join(APP_DIR, 'blog.db')
DEBUG = False

# Cookie Encryption
SECRET_KEY = 'WOW_MUCH_SECRET_VERY_UNIQUE_SO_SECURE_WOW'

# This is used by micawber, which will attempt to generate rich media
# embedded objects with maxwidth=800.
SITE_WIDTH = 800

# Create a Flask WSGI app and configure it using values from the module.
app = Flask(__name__)
app.config.from_object(__name__)

# FlaskDB is a wrapper for a peewee database that sets up pre/post-request
# hooks for managing database connections.
flask_db = FlaskDB(app)

# The `database` is the actual peewee database, as opposed to flask_db which is
# the wrapper.
database = flask_db.database

# Configure micawber with the default OEmbed providers (YouTube, Flickr, etc).
# We'll use a simple in-memory cache so that multiple requests for the same
# video don't require multiple network requests.
oembed_providers = bootstrap_basic(OEmbedCache())

from random import randint as rand

class Challenge:
    """
    Generates a challenge - 5 digit integer the user must
    encrypt with his private key. app knows the public key
    so decrypting the challenge should return the same number
    as the challenge.
    TODO: How secure is this?
    """

    def __init__(self):
        self.changeChallenge()
        self.duration = 120 #2 minutes

    def getChallenge(self):
        now = datetime.datetime.now()
        diff = now - self.last_time
        if diff.total_seconds() > self.duration:
            self.changeChallenge()
        return self.challenge

    def changeChallenge(self):
        print "Changing Challenge"
        self.challenge = str(rand(0, 10000))
        self.last_time = datetime.datetime.now()

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
def verify(challenge, response):
    publickey = RSA.importKey(
            open('publickey.pem').read())
    challenge_hash = SHA256.new(challenge).digest()

    response = (long(response),)
    return publickey.verify(challenge_hash, response)


def authenticate(challenge = None, response = None):
    """
    Easily changeable authentication plugin. TODO: Use challenge-response system
    """
    #success = password == app.config['ADMIN_PASSWORD']

    success = verify(challenge, response)
    print challenge, response, success

    login = Login()
    login.result = success
    login.password_entry = challenge+":"+response
    login.save()
    return success

def allowed_file(filename):
    return '.' in filename and \
            filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

class Login(flask_db.Model):
    """
    Models entries in the admin authentication attempt log
    """
    timestamp = DateTimeField(default=datetime.datetime.now, index=True)
    result = BooleanField(index=True)
    password_entry = TextField() #only used if result == False


    def save(self, *args, **kwargs):
        if self.result == True: #do not store passwords for successes
            self.password_entry = ''
        return super(Login, self).save(*args, **kwargs)

class Entry(flask_db.Model):
    """
    Models entries in the blog database
    """
    title = CharField()
    slug = CharField(unique=True)
    content = TextField()
    published = BooleanField(index=True)
    timestamp = DateTimeField(default=datetime.datetime.now, index=True)

    @property
    def html_content(self):
        """
        Generate HTML representation of the markdown-formatted blog entry,
        and also convert any media URLs into rich media objects such as video
        players or images.
        """
        hilite = CodeHiliteExtension(linenums=False, css_class='highlight')
        extras = ExtraExtension()
        try:
            markdown_content = markdown(self.content, extensions=[hilite, extras, 'latex'])
        except:
            markdown_content = markdown(self.content, extensions=[hilite, extras])
        oembed_content = parse_html(
            markdown_content,
            oembed_providers,
            urlize_all=True,
            maxwidth=app.config['SITE_WIDTH'])
        return Markup(oembed_content)

    def save(self, *args, **kwargs):
        # Generate a URL-friendly representation of the entry's title.
        if not self.slug:
            self.slug = re.sub('[^\w]+', '-', self.title.lower()).strip('-')
        ret = super(Entry, self).save(*args, **kwargs)

        # Store search content.
        self.update_search_index()
        return ret

    def update_search_index(self):
        # Create a row in the FTSEntry table with the post content. This will
        # allow us to use SQLite's awesome full-text search extension to
        # search our entries.
        try:
            fts_entry = FTSEntry.get(FTSEntry.entry_id == self.id)
        except FTSEntry.DoesNotExist:
            fts_entry = FTSEntry(entry_id=self.id)
            force_insert = True
        else:
            force_insert = False
        fts_entry.content = '\n'.join((self.title, self.content))
        fts_entry.save(force_insert=force_insert)

    @classmethod
    def public(cls):
        return Entry.select().where(Entry.published == True)

    @classmethod
    def drafts(cls):
        return Entry.select().where(Entry.published == False)

    @classmethod
    def search(cls, query):
        words = [word.strip() for word in query.split() if word.strip()]
        if not words:
            # Return an empty query.
            return Entry.select().where(Entry.id == 0)
        else:
            search = ' '.join(words)

        # Query the full-text search index for entries matching the given
        # search query, then join the actual Entry data on the matching
        # search result.
        return (FTSEntry
                .select(
                    FTSEntry,
                    Entry,
                    FTSEntry.rank().alias('score'))
                .join(Entry, on=(FTSEntry.entry_id == Entry.id).alias('entry'))
                .where(
                    (Entry.published == True) &
                    (FTSEntry.match(search)))
                .order_by(SQL('score').desc()))

class FTSEntry(FTSModel):
    """
    Models fast-text search capabilities in SQLite
    """
    entry_id = IntegerField(Entry)
    content = TextField()

    class Meta:
        database = database

def login_required(fn):
    @functools.wraps(fn)
    def inner(*args, **kwargs):
        if session.get('logged_in'):
            return fn(*args, **kwargs)
        return redirect(url_for('login', next=request.path))
    return inner

@app.route('/')
@app.route('/blog/')
def index():
    search_query = request.args.get('q')
    if search_query:
        query = Entry.search(search_query)
    else:
        query = Entry.public().order_by(Entry.timestamp.desc())

    # Instead of render_template, object_list creates pages
    return object_list(
        'blog.html',
        query,
        search=search_query,
        check_bounds=False)
@app.route('/login/', methods=['GET', 'POST'])
def login():
    app_challenge = app.config['Challenge']
    challenge = app_challenge.getChallenge()
    next_url = request.args.get('next') or request.form.get('next')
    if request.method == 'POST' and request.form.get('password'):
        password = request.form.get('password')
        if authenticate(challenge = challenge, response=password):
            session['logged_in'] = True
            session.permanent = True  # Use cookie to store session.
            flash('You are now logged in.', 'success')
            app_challenge.changeChallenge()
            return redirect(next_url or url_for('index'))
        else:
            app_challenge.changeChallenge()
            flash('Incorrect password.', 'danger')
    return render_template('login.html', next_url=next_url, challenge=challenge)

@app.route('/logout/', methods=['GET', 'POST'])
def logout():
    if request.method == 'POST':
        session.clear()
        return redirect(url_for('login'))
    return render_template('logout.html')


@app.route('/about/')
def about():
    return render_template('about.html')

@app.route('/create/', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST': #new file

        #user option #1: type in unput form
        if request.form.get('file') == 'text':

            if request.form.get('title') and request.form.get('content'):
                #valid input

                #create a new db entry
                entry = Entry.create(
                    title=request.form['title'],
                    content=request.form['content'],
                    published=request.form.get('published') or False)
                flash('Entry created successfully.', 'success')

                if entry.published:
                    return redirect(url_for('detail', slug=entry.slug))
                else:
                    return redirect(url_for('edit', slug=entry.slug))

            else:
                #invalid input
                flash('Title and Content are required.', 'danger')

        #user option #2: file upload
        else:
            file = request.files['upload']
            if file and allowed_file(file.filename):
                #upload ok and filetype legal
                content = file.read()
                title = ''
                if content[0] == '#':
                    title = content[1:content.find('\n')]
                    content = content[content.find('\n'):]
                elif request.form['title']:
                    title = request.form['title']
                else:
                    flash('You need to specify a title', 'danger')
                    return render_template('create.html')

                #create a new db entry
                entry = Entry.create(
                    title = title,
                    content = content,
                    published = request.form.get('published') or False)
                flash('Entry created successfully.', 'success')

                if entry.published:
                    return redirect(url_for('detail', slug=entry.slug))
                else:
                    return redirect(url_for('edit', slug=entry.slug))

            else:
                #invalid file
                flash('Error uploading file', 'danger')

    return render_template('create.html')

@app.route('/drafts/')
@login_required
def drafts():
    query = Entry.select().order_by(Entry.timestamp.desc())
    return object_list('blog.html', query, check_bounds=False)

@app.route('/<slug>/')
def detail(slug):
    if session.get('logged_in'): #admin searches all entries
        query = Entry.select()
    else: #guests search only public entries
        query = Entry.public()
    entry = get_object_or_404(query, Entry.slug == slug)
    return render_template('detail.html', entry=entry)

@app.route('/<slug>/edit/', methods=['GET', 'POST'])
@login_required
def edit(slug):
    entry = get_object_or_404(Entry, Entry.slug == slug)
    if request.method == 'POST':
        if request.form.get('title') and request.form.get('content'):
            entry.title = request.form['title']
            entry.content = request.form['content']
            entry.published = request.form.get('published') or False
            entry.save()

            flash('Entry saved successfully.', 'success')
            if entry.published:
                return redirect(url_for('detail', slug=entry.slug))
            else:
                return redirect(url_for('edit', slug=entry.slug))
        else:
            flash('Title and Content are required.', 'danger')

    return render_template('edit.html', entry=entry)

@app.template_filter('clean_querystring')
def clean_querystring(request_args, *keys_to_remove, **new_values):
    # We'll use this template filter in the pagination include. This filter
    # will take the current URL and allow us to preserve the arguments in the
    # querystring while replacing any that we need to overwrite. For instance
    # if your URL is /?q=search+query&page=2 and we want to preserve the search
    # term but make a link to page 3, this filter will allow us to do that.
    querystring = dict((key, value) for key, value in request_args.items())
    for key in keys_to_remove:
        querystring.pop(key, None)
    querystring.update(new_values)
    return urllib.urlencode(querystring)

@app.errorhandler(404)
def not_found(exc):
    return Response('<h3>Not found</h3>'), 404

def main():
    database.create_tables([Entry, FTSEntry, Login], safe=True)

    app.config['Challenge'] = Challenge()
    app.run(debug=True)

if __name__ == '__main__':
    main()
