from rest_framework import serializers
from .models import UserAccounts


class AccountSerializer(serializers.ModelSerializer):
    """
    Management for data serializing.

    """
    class Meta:
        model=UserAccounts
        fields=['id','name','email','password']
        extra_kwargs={
            'password':{'write_only':True}
        }

    def create(self, validated_data):
        """
        Method for creating hashed password.

        Parms:
            validated_data text: Validated data after serializing.

        Returns:
            instance: data afer including hashed password.
        """
        password=validated_data.pop('password',None)
        instance=self.Meta.model(**validated_data)

        if instance is not None:
            instance.set_password(password)
            instance.save()
            return instance