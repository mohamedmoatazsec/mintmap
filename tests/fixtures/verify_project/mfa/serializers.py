from rest_framework import serializers

from acme_tokens import PinPad


class PinSerializer(serializers.Serializer):
    pin = serializers.CharField()

    def validate_pin(self, value):
        if not PinPad.default().verify_pin(value):
            raise serializers.ValidationError("bad pin")
        return value

    def validate(self, attrs):
        return super().validate(attrs)
