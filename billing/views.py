import base64
import collections
import copy
import json
import os
import re
import urllib
from datetime import timedelta

import django.contrib.auth.password_validation as validators
import phpserialize
import pytz
import requests
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.core import exceptions
from django.core.mail import send_mail
from django.db.models import Count, F, Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.template.loader import render_to_string
from django.utils.encoding import force_text, force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.safestring import mark_safe
from ipware import get_client_ip
from rest_framework import permissions, serializers, status
from rest_framework import viewsets, generics, pagination
from rest_framework.authtoken.models import Token
from rest_framework.decorators import detail_route
from rest_framework.exceptions import ValidationError
from rest_framework.generics import UpdateAPIView, CreateAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from accounts.models import User
from accounts.permissions import IsUserOrReadOnly, UnauthenticatedOnly
from accounts.tokens import account_activation_token
from accounts.tokens import OneTimeToken


class BillingEventView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        if self.verify_request(request):
            return self.route_event(request)
        else:
            return Response("Yarr, don't be a pirate.", status=status.HTTP_403_FORBIDDEN)

    def route_event(self, request):
        if request.data.get('alert_name') == 'subscription_created':
            try:
                u = User.objects.get(email=request.data.get('email'))
                u.gold = True
                u.save()
                return Response("Subscribed", status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response("Gone", status=status.HTTP_404_NOT_FOUND)
        elif request.data.get('alert_name') == 'subscription_cancelled':
            try:
                u = User.objects.get(email=request.data.get('email'))
                u.gold = False
                u.save()
                return Response("Cancelled", status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response("Gone", status=status.HTTP_404_NOT_FOUND)
        else:
            return Response("Gone", status=status.HTTP_404_NOT_FOUND)

    def verify_request(self, request):
        public_key_encoded = getattr(settings, 'PADDLE_PKEY')[26:-25].replace('\n', '')
        public_key_der = base64.b64decode(public_key_encoded)

        # input_data represents all of the POST fields sent with the request
        # Get the p_signature parameter & base64 decode it.
        signature = request.data.get('p_signature')
        if not request.data.get('p_signature'):
            return False

        # Remove the p_signature parameter
        input_data = copy.deepcopy(request.data)
        del input_data['p_signature']

        # Ensure all the data fields are strings
        for field in input_data:
            input_data[field] = str(input_data[field])

        # Sort the data
        sorted_data = collections.OrderedDict(sorted(input_data.items()))

        # and serialize the fields
        serialized_data = phpserialize.dumps(sorted_data)

        # verify the data
        key = RSA.importKey(public_key_der)
        digest = SHA.new()
        digest.update(serialized_data)
        verifier = PKCS1_v1_5.new(key)
        signature = base64.b64decode(signature)
        return verifier.verify(digest, signature)