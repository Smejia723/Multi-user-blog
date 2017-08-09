import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

# template directory stuff
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Secret is uesd for hashed val
secret = 'superserial'

# render the template
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# Make a secured hashed value
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

# Make sure that the hashed value is valid
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

# Parent class for all the handlers
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # Uses the hashed value to store cookies here!
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # Secure cookie
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # Setting a secure cookie user_id = user id from  the app engine
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # Sets the cookie to nothing and returning user to Path=/
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # Request calls a secure cookie called userID to sets self.user to user
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    # Renders a users posts
    def render_post(response, post):
        response.out.write('<b>' + post.subject + '</b><br>')
        response.out.write(post.content)

# Starting point page
class MainPage(BlogHandler):
    def get(self):
        self.render('welcome.html')

# User stuff
# Make a string with 5 letters
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

# Takes name, password to make a new salt that does not exist
# Stored in Database
# Salt (SaltStack Platform):
# Is a open-source configuration management software and remote execution engine.
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

# Verifies password turns it ino hash form matching to database
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

# User object that is strored in database
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()
    #Looks up by user.by_id number
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())
    #looks up by name for user
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u
    #Creates a new user
    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)
    #A decorator method that can look up user
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


#####work on post handles here!!!!!
# Blog stuff
def blog_key(name='default'):
    return db.Key.from_path('/', name)

# Create our post entity
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    # create author to appear in each of our posts
    author = db.StringProperty(required=True)
    likes = db.IntegerProperty(default=0)
    usersliked = db.StringListProperty()
    usersdisliked = db.StringListProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

# Show the posts in order set
class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts=posts)

# Events after you create a post
class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        comments = Comment.all().filter(
            'post_id =', int(post_id)).order('created')

        error = "Both title and comment are required fields"

        self.render('permalink.html',
            post=post,
            comments=comments,
            error=error)

# Edits posts
class EditPost(BlogHandler):
    def get(self, post_id):

        key = db.Key.from_path('Post',
        int(post_id),
        parent=blog_key())
        query = db.get(key)

        if not query:
            self.error(404)
            return self.render('error.html')

        # If user is logged in, proceed
        if self.user:
            username = self.user.name
            author = query.author
            if author == username:
                flag = True
                self.render('editpost.html',
                query=query, flag=flag)
            else:
                flag = False
                self.render('editpost.html',
                query=query, flag=flag)
        # Redirect to login
        else:
            return self.redirect('/login')

    # waits for the right event triggers
    def post(self, post_id):
        key = db.Key.from_path('Post',
        int(post_id),
        parent=blog_key())
        query = db.get(key)

        if self.user:
            username = self.user.name
            author = query.author
            if author == username:
                flag = True
                self.render("editpost.html",
                query=query,
                flag=flag)
            else:
                flag = False
                self.render("editpost.html",
                query=query,
                flag=flag)
        # Redirect to login
        else:
            return self.redirect('/login')

        if query is None:
            self.error(404)
            return self.render('error.html')

        subject = self.request.get('subject')
        content = self.request.get('content')
        username = self.user.name
        author = query.author
        if author == username:
            if "update" in self.request.POST:
                if subject and content:
                    subject = query.subject
                    content = query.content
                    query.put()
                    return self.redirect('/%s' % str(var.key().id()))
                else:
                    error = "Both subject and content are required fields"
                    self.render(
                        "editpost.html",
                        subject=subject,
                        content=content,
                        error=error)

            if "delete" in self.request.POST:
                if not self.user:
                    return self.redirect('/asciichan2/')

                post_id = Post.get_by_id(int(post_id),
                parent=blog_key())
                return self.redirect('/delete-confirmation/%s' %
                                     str(post_id.key().id()))

            if "cancel" in self.request.POST:
                if not self.user:
                    return self.redirect('/asciichan2/')

                return self.redirect(
                    '/postandcomments/%s' % str(post_id))
        else:
            self.render('error.html')

# Deletes post
class DelConfirmation(BlogHandler):
    def get(self, post_id):
        if post_id:
            if self.user:
                key = db.Key.from_path('Post', int(post_id),
                parent=blog_key())
                query = db.get(key)
                if query:
                    self.render('delete-confirmation.html',
                    query=query)
                else:
                    self.error(404)
                    return self.render('error.html')
            else:
                return self.redirect('/login')

    def post(self, post_id):

        if post is not None:
            key = db.Key.from_path('Post',
            int(post_id),
            parent=blog_key())
            query = db.get(key)

            username = self.user.name
            author = query.author

            if username == author:
                if "delete-post" in self.request.POST:
                    delVal = Post.get_by_id(int(post_id),
                    parent=blog_key())
                    delVal.delete()
                    return self.redirect('/')
                if "cancel-delete" in self.request.POST:
                    return self.redirect('/')
            else:
                return self.redirect('/asciichan2/')
        else:
            return self.redirect('/login')


# Creates new post
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render('newpost.html')
        else:
            return self.redirect('/login')

    def post(self):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.name
        postid = self.request.get('id')

        if subject and content:
            p = Post(
                parent=blog_key(),
                subject=subject,
                content=content,
                author=author,
                postid=postid)
            p.put()
            return self.redirect('/asciichan2/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render(
                "newpost.html",
                subject=subject,
                content=content,
                error=error,
                author=author,
                postid=postid)

# Comment section and the database table
class Comment(db.Model):
    author = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    postid = db.StringProperty(required=True)

    # Render our individual comment template
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comments.html", p=self)

# Get the original post content
# Key class to render our blog posts
class Comments(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            allcomments = db.GqlQuery("""select * from Comment where
                                      postid = :post_id
                                      order by created asc""",
                                      post_id=post_id)
            statuscheck = db.GqlQuery(
                "select * from Comment where postid = :post_id",
                post_id=post_id).get()
            if statuscheck is None:
                statuscheck = "No comments, submit a comment above."
                self.render(
                    "/postandcomments.html",
                    post=post,
                    allcomments=allcomments,
                    statuscheck=statuscheck)
            else:
                self.render(
                    "/postandcomments.html",
                    post=post,
                    allcomments=allcomments)
        else:
            return self.redirect('/login')

    # Insert into the comments table
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        # Get our comments where the post_id is the post we are on
        allcomments = db.GqlQuery("""select * from Comment where
                                  postid = :post_id order by created asc""",
                                  post_id=post_id)
        author = self.user.name
        content = self.request.get('content')
        if not self.user:
            return self.redirect('/login')

        # Check for the right event
        if "insert" in self.request.POST:
            if content:
                c = Comment(
                    post=post.key,
                    content=content,
                    author=author,
                    postid=post_id)
                c.put()
                self.render(
                    "/postandcomments.html",
                    post=post,
                    content=content,
                    author=author,
                    allcomments=allcomments)
            else:
                comment_error = True
                self.render(
                    "/postandcomments.html",
                    post=post,
                    content=content,
                    author=author,
                    allcomments=allcomments,
                    comment_error=comment_error)

# Edit comments
class EditComment(BlogHandler):
    def get(self, comment_id):
        # Attempt to get the comment  id
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        if not comment:
            self.error(404)
            return self.render('error.html')

        if self.user:
            username = self.user.name
            author = comment.author
        else:
            return self.redirect('/login')

        # If logged in user name matches the author name
        if author == username:
            # Pass in flag into template
            flag = True
            self.render('editcomment.html',
                comment=comment,
                flag=flag)
        else:
            flag = False
            self.render('editcomment.html',
                comment=comment,
                flag=flag)

    # Use the post method to update
    def post(self, comment_id):
        content = self.request.get('content')
        postKey = db.Key.from_path('Post', int(post_id),
        parent=blog_key())
        key = db.Key.from_path('Comment',
        int(comment_id))
        comment = db.get(key)

        if self.user:
            username = self.user.name
            author = comment.author
        else:
            return self.redirect('/login')

        if username == author:
            if "update" in self.request.POST:
                if content:
                    comment.content = content
                    comment.put()
                    return self.redirect('/asciichan2/')
                else:
                    error = True
                    self.render(
                        "/editcomment.html",
                        comment=comment,
                        content=content,
                        error=error)
        else:
            return self.render('error.html')

        # Trigger delete comment if it is our user
        if "delete" in self.request.POST:
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)
            return self.redirect("/deletecomment/%s" % str(comment.key().id()))

        # Trigger cancel changes if it is our user
        if "cancel" in self.request.POST:
            if not self.user:
                return self.redirect('/asciichan2/')

            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)
            postid = comment.postid
            return self.redirect('/postandcomments/%s' % str(postid))


# Actually delete the comment
class DeleteComment(BlogHandler):
    def get(self, comment_id):
        if self.user:
            username = self.user.name
            author = comment.author
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)
            if not comment:
                self.error(404)
                return self.render('error.html')

            self.render('deletecomment.html', comment=comment)
        else:
            return self.redirect('/login')

    def post(self, comment_id):
        # First get the post_id using the comment_id
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        if not self.user:
            return self.redirect('/login')

        if not comment:
            self.error(404)
            return self.render('error.html')
        comment_author = comment.author

        username = self.user.name

        if username == comment_author:
            if "delete-comment" in self.request.POST:
                key = db.Key.from_path('Comment', int(comment_id))
                comment = db.get(key)
                comment.delete()
                return self.redirect("/")
            if "cancel-delete" in self.request.POST:
                return self.redirect("/")
        else:
            return self.redirect('/asciichan2/')

#####work on post handles here!!!!!


# Signup template
class Signup(BlogHandler):
    def get(self):
        self.render('signup-form.html')

    # Get all the values from the request
    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        # Check if all the values are valid
        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        # If have_error is true, return error messages
        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    # Raises an error but should be overwritten by unit2signup
    def done(self, *a, **kw):
        raise NotImplementedError


# Inherits from signup and overwrites done
class Unit2Signup(Signup):
    def done(self):
        return self.redirect('/unit2/welcome?username=' + 
            self.username)

# Register class inherits from signup
class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', 
                error_username=msg)
        else:
            u = User.register(self.username, 
                self.password, 
                self.email)
            u.put()
            self.login(u)
            return self.redirect('/asciichan2/')

# Setting up login, conformation, and error.
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html',
        error=self.request.get('error'))

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            return self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)

class Error(BlogHandler):
    def get(self):
        self.render('error.html')

class Logout(BlogHandler):
    def get(self):
        self.logout()
        return self.redirect('/login')

# Inherits from bloghandler, does the welcome screen
class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            return self.redirect('/signup')

# Routing stuff
class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            return self.redirect('/unit2/signup')

# The routes to the site
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/signup',
                                Unit2Signup),
                               ('/unit2/welcome',
                                Welcome),
                               ('/asciichan2/?',
                                BlogFront),
                               ('/asciichan2/([0-9]+)',
                                PostPage),
                               ('/asciichan2/newpost',
                                NewPost),
                               ('/asciichan2/postandcomments/([0-9]+)',
                                Comments),
                               ('/asciichan2/editpost/([0-9]+)',
                                EditPost),
                               ('/asciichan2/delete-confirmation/([0-9]+)',
                                DelConfirmation),
                               ('/asciichan2/editcomment/([0-9]+)',
                                EditComment),
                               ('/asciichan2/deletecomment/([0-9]+)',
                                DeleteComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/error', Error),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ],
                              debug=True)