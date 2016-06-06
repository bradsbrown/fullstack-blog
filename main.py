#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
'''Imports necessary for web render, page templates, hash generation'''
import webapp2
import os
import jinja2
import re
import random
import string
import hashlib

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

'''Regex expressions for validation checker'''
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PW_RE = re.compile("^.{3,20}$")
EMAIL_RE = re.compile("^[\S]+@[\S]+.[\S]+$")

'''Queries to return db data'''
LIKES_QUERY = "SELECT * FROM Likes WHERE post_id = %s"
USER_LIKE_QUERY = "SELECT * FROM Likes WHERE username=:1 AND post_id=:2"
COMMENTS_QUERY = "SELECT * FROM Comments WHERE\
                  post_id = %s ORDER BY created DESC"


def valid_entry(string, field):
    '''Validates a user submission against
    regex expressions for a valid entry.'''
    if field == "usr":
        return string and USER_RE.match(string)
    if field == "pw":
        return string and PW_RE.match(string)
    if field == "em":
        return not string or EMAIL_RE.match(string)


def make_salt():
    '''generates a salt string for password creation'''
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, password, salt=None):
    '''takes a password and username, generates a hash to store for pw'''
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + password + salt).hexdigest()
    return '%s|%s' % (salt, h)


def check_valid_pw(name, password, h):
    '''takes a name, password, and hash, returns True if the name and pw
    generate a has that matches (i.e. the name/pw combo is valid)'''
    salt = h.split('|')[0]
    return h == make_pw_hash(name, password, salt)


def make_secure_val(user_id):
    '''creates a hashed value for the user_id cookie'''
    return '%s|%s' % (user_id, hashlib.sha256(str(user_id)).hexdigest())


def check_secure_val(cookie_val):
    '''validates that a given cookie is valid for the stated user_id'''
    user_id = cookie_val.split('|')[0]
    return cookie_val == make_secure_val(user_id)


class Handler(webapp2.RequestHandler):
    '''write, render_str, and render are generic functions used to write
    out HTML using jinja2 templates'''
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        '''take a cookie name and value, sets a cookie with the value hashed'''
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        '''returns cookie for the given name if it is a validly hashed cookie,
        or returns False in all other cases'''
        cookie_val = self.request.cookies.get(name)
        if cookie_val and cookie_val != '':
            if check_secure_val(cookie_val):
                return cookie_val
            else:
                return False
        else:
            return False

    def get_id_from_hash(self, hash):
        '''returns the user ID from a hashed cookie'''
        return int(hash.split('|')[0])

    def login(self, user):
        '''sets a secure cookie for a logged in user'''
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        '''clears the user_id cookie to log a user out'''
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def render_post(self, form, id='0', **params):
        '''helper function to render either a post or comment page with all
        valid parameters necessary to fill potentially necessary HTML fields'''
        if id == '0':
            self.render("main.html")
        else:
            user_hash = self.read_secure_cookie('user_id')
            user_id = self.get_id_from_hash(user_hash)
            user = Users.get_by_id(user_id)
            username = user.username

            blog = Posts.get_by_id(int(id))

            comments = db.GqlQuery(COMMENTS_QUERY % id)

            likes = db.GqlQuery(LIKES_QUERY % id)
            like_count = likes.count()

            does_like = db.GqlQuery(USER_LIKE_QUERY, username, int(id))
            if does_like.count() == 1:
                has_liked = True
            elif does_like.count() == 0:
                has_liked = False

            self.render(form,
                        blog=blog,
                        comments=comments,
                        like_count=like_count,
                        user_id=user_id,
                        username=username,
                        has_liked=has_liked,
                        **params)


class Comments(db.Model):
    '''db to track comments, including user id and name for commenter,
    the id for the post being commented on, and the comment itself'''
    user_id = db.IntegerProperty(required=True)
    username = db.StringProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class Likes(db.Model):
    '''db to track user likes, includes id and name of liking user, as well
    as the id of the post being liked'''
    user_id = db.IntegerProperty(required=True)
    username = db.StringProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class Posts(db.Model):
    '''db to contain posts. Includes post subject and content, as well as
    posting user's id and name.'''
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    username = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class Users(db.Model):
    '''db to track users. Includes username, and hashed pw, as well as
    optional email address.'''
    username = db.StringProperty(required=True)
    password_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)


class MainHandler(Handler):
    '''Renders the blog's main page - includes the 10 most recent posts.'''
    def render_main(self):
        blogs = db.GqlQuery("SELECT * FROM Posts ORDER BY\
                            created DESC LIMIT 10")
        self.render("main.html", blogs=blogs)

    def get(self):
        user_hash = self.read_secure_cookie('user_id')
        if user_hash:
            self.render_main()

        else:
            self.redirect('/login')


class SubmitHandler(Handler):
    '''Handles New Post submission.'''
    def render_submit(self, subject="", content="", error=""):
        self.render("submit.html",
                    subject=subject,
                    content=content,
                    error=error)

    def get(self):
        user_hash = self.read_secure_cookie('user_id')
        if user_hash:
            self.render_submit()
        else:
            self.redirect('/login')

    def post(self):
        user_hash = self.read_secure_cookie('user_id')
        if user_hash:
            user_id = int(self.get_id_from_hash(user_hash))
            user = Users.get_by_id(user_id)
            username = user.username
            subject = self.request.get("subject")
            content = self.request.get("content")

            if subject and content:
                b = Posts(subject=subject,
                          content=content,
                          user_id=user_id,
                          username=username)
                b.put()
                b_id = int(b.key().id())
                self.redirect("/%s" % b_id)

            else:
                error = "Please enter both a subject and content!"
                self.render_submit(subject=subject,
                                   content=content,
                                   error=error)
        else:
            self.redirect('/login')


class PostHandler(Handler):
    '''Handles the page for displaying an individual post.'''
    def get(self, id=0):
        user_hash = self.read_secure_cookie('user_id')
        params = {}
        if user_hash:
            blog = Posts.get_by_id(int(id))

            if not blog:
                self.error(404)
                return

            self.render_post("post.html", id, **params)

        else:
            self.redirect('/login')


class SignupHandler(Handler):
    '''Handles enrollment for a new user, validating each field for correct
    format, necessary content, pw match, then enrolling the user in the db.
    Sends user to a welcome page once successfully enrolled.'''
    def get(self):
        self.render("signup.html", username="", pw="", email="")

    def post(self):
        error = False
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        params = dict(username=username, email=email)

        if not valid_entry(username, "usr"):
            params['error_username'] = "Sorry! That's not a valid user name."
            error = True

        if not valid_entry(password, "pw"):
            params['error_pw'] = "Sorry! That isn't a valid password."
            error = True
        elif password != verify:
            params['error_match'] = "Your passwords don't match."
            error = True

        if not valid_entry(email, "em"):
            params['error_email'] = "Sorry, that's not a valid email."
            error = True

        q = Users.gql("WHERE username = '%s'" % username)
        if q.count() > 0:
            params['error_userexist'] = "That user already exists!"
            error = True

        if error:
            self.render('signup.html', **params)
        else:
            password_hash = make_pw_hash(username, password)
            u = Users(username=username,
                      password_hash=password_hash,
                      email=email)
            u.put()
            user_id = int(u.key().id())
            self.set_secure_cookie('user_id', user_id)
            self.redirect('/welcome')


class WelcomeHandler(Handler):
    "displays welcome page for new or returning user, including username"
    def get(self):
        user_hash = self.read_secure_cookie('user_id')
        if user_hash:
            user = Users.get_by_id(self.get_id_from_hash(user_hash))
            self.render("confirmed.html", username=user.username)

        else:
            self.redirect('/login')


class LoginHandler(Handler):
    '''Handles user login page, verifying user exists and pw is valid.
    In cases of user error, displays a helpful error message.
    In case of valid login, sets the user cookie then passes to
    the welcome page.'''
    def get(self):
        self.render("login.html", username='')

    def post(self):
        error = False
        username = self.request.get("username")
        password = self.request.get("password")

        params = dict(username=username)

        q = Users.gql("WHERE username = '%s'" % username)
        if q.count() == 0:
            params['error_user'] = "That user does not exist!"
            error = True
        else:
            user = q.get()
            password_hash = user.password_hash
            if not check_valid_pw(username, password, password_hash):
                params['error_pw'] = "Wrong password!"
                error = True

        if error:
            self.render("login.html", **params)
        else:
            self.set_secure_cookie('user_id', user.key().id())
            self.redirect('/welcome')


class LogoutHandler(Handler):
    '''Logs user out, returns to login page'''
    def get(self):
        self.logout()
        self.redirect('/login')


class CommentHandler(Handler):
    '''Handles posting new comments on a blog post, then returns to the
    post display page.'''
    def get(self, id=0):
        user_hash = self.read_secure_cookie('user_id')
        if user_hash:
            blog = Posts.get_by_id(int(id))

            if not blog:
                self.error(404)
                return

            self.render_post("comment.html", id)

        else:
            self.redirect('/login')

    def post(self, id=0):
        user_hash = self.read_secure_cookie('user_id')
        if user_hash:
            user_id = self.get_id_from_hash(user_hash)
            comment = self.request.get("comment")
            user = Users.get_by_id(self.get_id_from_hash(user_hash))
            username = user.username
            c = Comments(user_id=user_id,
                         username=username,
                         comment=comment,
                         post_id=int(id))
            c.put()
            self.redirect("/%s" % id)


class LikeHandler(Handler):
    '''Sets a like/unlike for a post, checks to prevent a user from liking
    their own posts. The form itself only displays links to like/unlike
    when applicable, but in case a like is called via URL,
    this class shows helpful error messages where necessary.'''
    def get(self, flag, id=0):
        user_hash = self.read_secure_cookie('user_id')
        if user_hash:
            blog = Posts.get_by_id(int(id))
            user_id = self.get_id_from_hash(user_hash)
            params = {}

            if user_id == blog.user_id:
                params["error_selflike"] = "You can't like or unlike\
                                            your own posts!"
                self.render_post("post.html", id, **params)

            else:
                user = Users.get_by_id(user_id)
                username = user.username
                likes = db.GqlQuery(USER_LIKE_QUERY, username, int(id))
                if likes.count() == 1:
                    has_liked = True
                elif likes.count() == 0:
                    has_liked = False
                if not has_liked:
                    if flag == 'add':
                        like = Likes(user_id=user_id,
                                     username=username,
                                     post_id=int(id))
                        like.put()
                        self.redirect("/%s" % id)
                    elif flag == 'del':
                        params["error_hasliked"] = "You haven't liked\
                                                    this yet!"
                        self.render_post("post.html", id, **params)

                else:
                    if flag == 'add':
                        params["error_hasliked"] = "You've already liked this!"
                        self.render_post("post.html", id, **params)
                    elif flag == 'del':
                        like = likes.get()
                        like.delete()
                        self.redirect("/%s" % id)
        else:
            self.redirect("/login")


class DeleteHandler(Handler):
    '''Handles post/comment deletion after verifying the request is being
    sent by the post/comment creator. The form itself only shows links to
    delete when the creator is viewing, but this checks for a case where
    a deletion is called via URL by another user, and redirects them
    back to the post page.'''
    def get(self, mode, id):
        user_hash = self.read_secure_cookie('user_id')
        if user_hash:
            user_id = self.get_id_from_hash(user_hash)
            if mode == 'comment':
                comment = Comments.get_by_id(int(id))
                redirect_id = comment.post_id
                if user_id == comment.user_id:
                    comment.delete()
                    self.redirect('/%s' % redirect_id)
                else:
                    self.redirect(self.request.referer)
            if mode == 'post':
                post = Posts.get_by_id(int(id))
                if user_id == post.user_id:
                    post.delete()
                    self.redirect('/')
                else:
                    self.redirect(self.request.referer)
        else:
            self.redirect('/login')


class EditHandler(Handler):
    '''Allows a user to edit their own posts and comments. Edit links are only
    shown on the form when viewed by the creator, but this function also checks
    to validate the creator, and redirects others back to the post page.'''
    def get(self, mode, id=0):
        user_hash = self.read_secure_cookie('user_id')
        if user_hash:
            user_id = int(self.get_id_from_hash(user_hash))
            user = Users.get_by_id(user_id)
            username = user.username

            comments = db.GqlQuery(COMMENTS_QUERY % id)

            likes = db.GqlQuery(LIKES_QUERY % id)
            like_count = likes.count()

            does_like = db.GqlQuery(USER_LIKE_QUERY, username, int(id))
            if does_like.count() == 1:
                has_liked = True
            elif does_like.count() == 0:
                has_liked = False

            if mode == 'comment':
                comment = Comments.get_by_id(int(id))
                blog = Posts.get_by_id(comment.post_id)
                redirect_id = comment.post_id
                if user_id == comment.user_id:
                    self.render("comment.html",
                                comments=comments,
                                like_count=like_count,
                                user_id=user_id,
                                blog=blog,
                                username=username,
                                has_liked=has_liked,
                                comment=comment.comment)
                else:
                    self.redirect('/%s' % redirect_id)
            if mode == 'post':
                post = Posts.get_by_id(int(id))
                if user_id == post.user_id:
                    self.render("submit.html",
                                subject=post.subject,
                                content=post.content)
                else:
                    self.redirect('/%s' % id)
        else:
            self.redirect('/login')

    def post(self, mode, id=0):
        user_hash = self.read_secure_cookie('user_id')
        if user_hash:
            if mode == "comment":
                c = Comments.get_by_id(int(id))
                comment = self.request.get("comment")
                c.comment = comment
                c.put()
                self.redirect('/%s' % c.post_id)
            elif mode == "post":
                p = Posts.get_by_id(int(id))
                subject = self.request.get("subject")
                content = self.request.get("content")
                p.subject = subject
                p.content = content
                p.put()
                self.redirect('/%s' % id)
        else:
            self.redirect('/login')


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/newpost', SubmitHandler),
    ("/(\d+)", PostHandler),
    ('/signup', SignupHandler),
    ('/welcome', WelcomeHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/comment/(\d+)', CommentHandler),
    ('/like/(add|del)/(\d+)', LikeHandler),
    ('/delete/(comment|post)/(\d+)', DeleteHandler),
    ('/edit/(comment|post)/(\d+)', EditHandler)
], debug=True)
