import os

from .settings import env, BASE_DIR

try:
    DATABASES = {
        'default': env.db(),
    }
except:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
        }
    }
