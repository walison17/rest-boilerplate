import os

from .settings import env

if env('MAILGUN_API_KEY', default=False):
    ANYMAIL = {
        # (exact settings here depend on your ESP...)
        "MAILGUN_API_KEY": env("MAILGUN_API_KEY"),
        "MAILGUN_SENDER_DOMAIN": env('MAILGUN_SENDER_DOMAIN', default='getmakerlog.com'),  # your Mailgun domain, if needed
    }
    EMAIL_BACKEND = "anymail.backends.mailgun.EmailBackend"  # or sendgrid.EmailBackend, or...
    DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_DOMAIN', default="hello@getmakerlog.com")  # if you don't already have this in settings
elif env('SENDGRID_API_KEY', default=False):
    ANYMAIL = {
        "SENDGRID_API_KEY": env("SENDGRID_API_KEY")
    }
    EMAIL_BACKEND = "anymail.backends.sendgrid.EmailBackend"
    DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_DOMAIN', default="hello@getmakerlog.com")
elif env('MAILJET_API_KEY', default=False) and env('MAILJET_SECRET_KEY', default=False):
    ANYMAIL = {
        "MAILJET_API_KEY": env("MAILJET_API_KEY"),
        "MAILJET_SECRET_KEY": env("MAILJET_SECRET_KEY"),
    }
    EMAIL_BACKEND = "anymail.backends.mailjet.EmailBackend"
    DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_DOMAIN', default="hello@getmakerlog.com")
elif env('SPARKPOST_API_KEY', default=False):
    EMAIL_BACKEND = "anymail.backends.sparkpost.EmailBackend"
    ANYMAIL = {
        "SPARKPOST_API_KEY": env('SPARKPOST_API_KEY'),
    }
    DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_DOMAIN', default="hello@getmakerlog.com")
elif env('AWS_ACCESS_KEY_ID', default=False) and env('AWS_SECRET_ACCESS_KEY', default=False):
    os.environ["AWS_ACCESS_KEY_ID"] = env('AWS_ACCESS_KEY_ID')
    os.environ["AWS_SECRET_ACCESS_KEY"] = env('AWS_SECRET_ACCESS_KEY')
    os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'
    EMAIL_BACKEND = "anymail.backends.amazon_ses.EmailBackend"
else:
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

