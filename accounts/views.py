from rest_framework.exceptions import AuthenticationFailed
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import AccountSerializer
from .models import UserAccounts
import jwt,datetime


class RegisterView(APIView):
    """
    Method for Registering User.

    """
    def post(self,request):
        """
        Method for handling post request.

        Parms:
            request : Post request.

        Returns:
            Serialized_data JSONResponse: Response for the post request.
        """
        serializers=AccountSerializer(data=request.data)
        serializers.is_valid(raise_exception=True)
        serializers.save()
        return Response(serializers.data)



class LoginView(APIView):
    """
    Method for login with user credentials.
    """
    def post(self,request):
        """
        Method for handling post request.

        Parms:
            request : Post request.

        Returns:
            Jwt-token JSONResponse: Response data for creating cookies with jwt token for the post request.
        """
        email=request.data['email']
        password=request.data['password']

        user=UserAccounts.objects.filter(email=email).first()
        if user is None:
            raise AuthenticationFailed('User not found')

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect Password')

        payload={
            "id":user.id,
            "exp":datetime.datetime.utcnow()+datetime.timedelta(minutes=60),
            "iat":datetime.datetime.utcnow()

        }

        token=jwt.encode(payload,'secret',algorithm='HS256')

        response=Response()
        
        response.set_cookie(key='jwt',value=token,httponly=True)

        response.data={
            "jwt":token
        }

        return response



class UserView(APIView):
    """
    Method for handling authentication and response user data.
    """
    def get(self,request):
        """
        Method for handling get request.

        Parms:
            request : Get request.

        Returns:
            user_data JSONResponse: Response for the get request.
        """
        token=request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('User not found!')

        try:
            payload= jwt.decode(token,'secret',algorithms='HS256')
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated')

        user=UserAccounts.objects.filter(id=payload['id']).first()

        serializer=AccountSerializer(user)
        return Response(serializer.data)

        

class LogoutView(APIView):
    """
    Method for logout and clearing cookies token credentials.
    """
    def post(self,request):
        """
        Method for handling post request.

        Parms:
            request : Post request.

        Returns:
            Logout_message JSONResponse: Response for the post request.
        """
        response=Response()
        response.delete_cookie('jwt')
        response.data={
            'message':'Succesfully Logut'
        }
        return response