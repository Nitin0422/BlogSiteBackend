from django.contrib import admin
from account.models import User
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

# Registering the custom user model
class UserModelAdmin(BaseUserAdmin):
    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserModelAdmin
    # that reference specific fields on auth.User.
    list_display = ["id", "email", "name", "country", "is_admin", "created_at", "updated_at"]
    list_filter = []
    fieldsets = [
        ("User Credentials", {"fields": ["email", "password"]}),
        ("Personal info", {"fields": ["name", "country"]}),
        ("Account Status", {"fields": ["is_verified", "is_active",]}),
        ("Permissions", {"fields": ["is_admin"]}),
    ]
    # add_fieldsets is not a standard ModelAdmin attribute. UserModelAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = [
        (
            None,
            {
                "classes": ["wide"],
                "fields": ["email","name", "country", "password1", "password2"],
            },
        ),
    ]
    search_fields = ["id", "email", "name", "country"]
    ordering = ["email", "country"]
    filter_horizontal = []

admin.site.register(User, UserModelAdmin)
