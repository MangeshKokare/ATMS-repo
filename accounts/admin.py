from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.core.exceptions import PermissionDenied
from .models import CustomUser, Team
from .models import Comment
from .models import SubTask

class CustomUserAdmin(UserAdmin):
    # Fields shown when viewing/editing a user in admin
    fieldsets = (
        (None, {
            "fields": (
                "username", "password", "email", "role",
                "emp_id", "department", "campus", "school", "phone_number"
            )
        }),
        ("Permissions", {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        ("Important dates", {"fields": ("last_login", "date_joined")}),
    )

    # Fields shown when creating a user in admin
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": (
                "username", "email", "password1", "password2", "role",
                "emp_id", "department", "campus", "school", "phone_number"
            ),
        }),
    )

    # ADD SCHOOL HERE 👇
    list_display = [
        "username", "email", "role", "emp_id",
        "get_department", "campus", "get_school",  # 👈 School Column
        "phone_number", "is_staff"
    ]

    search_fields = ["username", "email", "emp_id", "department__name", "school__name"]
    ordering = ["username"]

    # Display multiple departments
    def get_department(self, obj):
        return ", ".join([dept.name for dept in obj.department.all()])
    get_department.short_description = "Department"

    # Display school name
    def get_school(self, obj):
        return obj.school.name if obj.school else "-"
    get_school.short_description = "School"

    def save_model(self, request, obj, form, change):
        # Prevent non-superusers from creating HODs or Admins
        if obj.role in ['hod', 'admin'] and not request.user.is_superuser:
            raise PermissionDenied(f"You don't have permission to create a {obj.role.upper()}.")
        super().save_model(request, obj, form, change)


admin.site.register(CustomUser, CustomUserAdmin)


from .models import Project

@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = (
        'name',
        'created_by',
        'created_at',
        'start_date',
        'end_date',
        'get_departments',
        'get_schools',        # ⭐ Added
        'status',
    )

    list_filter = (
        'created_at',
        'start_date',
        'end_date',
        'department',        # M2M filter
        'department__school',   # ⭐ Filter by schools too
    )

    search_fields = (
        'name',
        'description',
        'keyword',   # ❌ remove if keyword no longer exists
        'created_by__username',
        'created_by__first_name',
        'created_by__last_name',
    )

    filter_horizontal = ('department',)

    # ----------------------
    # Departments Column
    # ----------------------
    def get_departments(self, obj):
        return ", ".join([dept.name for dept in obj.department.all()])
    get_departments.short_description = "Departments"

    # ----------------------
    # ⭐ Schools Column
    # ----------------------
    def get_schools(self, obj):
        schools = obj.department.values_list("school__name", flat=True).distinct()
        return ", ".join(schools)
    get_schools.short_description = "Schools"


@admin.register(Team)
class TeamAdmin(admin.ModelAdmin):
    list_display = ('name', 'staff')   # show name & staff in list
    search_fields = ('name', 'staff__username')  # add search support
    filter_horizontal = ('members',)   # nicer UI for selecting members

    

from django.contrib import admin
from .models import Task

@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    list_display = (
        'title',
        'project',
        'assigned_to',
        'assigned_by',
        'status',
        'priority',
        'due_date',
        'created_at',
    )
    
    list_filter = ('status', 'priority', 'project', 'assigned_by')
    search_fields = ('title', 'assigned_to__username', 'assigned_by__username', 'project__name')
    ordering = ('due_date', 'priority')
    date_hierarchy = 'due_date'
    
    fieldsets = (
        (None, {
            'fields': (
                'title',
                'description',
                'project',
                'assigned_to',
                'assigned_by',
                'team',
                'parent_task',
            )
        }),
        ('Task Info', {
            'fields': ('status', 'priority', 'due_date', 'sprint')
        }),
        ('Timers', {
            'fields': ('start_time', 'end_time', 'total_time', 'total_time_seconds')
        }),
    )

    readonly_fields = ('created_at', 'updated_at', 'total_time', 'total_time_seconds')



from .models import Campus, School, Department
# ---------------- CAMPUS ----------------
@admin.register(Campus)
class CampusAdmin(admin.ModelAdmin):
    list_display = ('name',)  # Show campus name in admin list
    search_fields = ('name',)  # Enable search by campus name

# ---------------- SCHOOL ----------------
@admin.register(School)
class SchoolAdmin(admin.ModelAdmin):
    list_display = ('name', 'campus')  # Show school name & campus
    search_fields = ('name', 'campus__name')  # Search by school or campus name
    list_filter = ('campus',)  # Filter schools by campus

# ---------------- DEPARTMENT ----------------
@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ('name', 'campus', 'school')  # Show department, campus, school
    search_fields = ('name', 'campus__name', 'school__name')  # Search by name, campus, school
    list_filter = ('campus', 'school')  # Filter by campus & school

@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    list_display = (
        'task',
        'user',
        'get_role',      # 👈 Role column added
        'short_text',
        'created_at',
    )

    list_filter = ('user__role', 'created_at')
    search_fields = ('text', 'user__username', 'task__title', 'user__role')
    ordering = ('-created_at',)

    readonly_fields = ('created_at',)

    fieldsets = (
        ('Comment Info', {
            'fields': (
                'task',
                'user',
                'text',
                'created_at',
            )
        }),
    )

    def short_text(self, obj):
        return (obj.text[:50] + "...") if len(obj.text) > 50 else obj.text
    short_text.short_description = "Comment"

    def get_role(self, obj):
        return obj.user.role if obj.user else "-"
    get_role.short_description = "Role"



@admin.register(SubTask)
class SubTaskAdmin(admin.ModelAdmin):
    list_display = (
        'title',
        'task',
        'assigned_to',
        'status',
        'deadline',
        'is_completed',
        'time_spent_seconds',
        'start_time',
        'end_time',
    )

    list_filter = ('status', 'assigned_to', 'deadline', 'is_completed')
    search_fields = ('title', 'task__title', 'assigned_to__username')
    ordering = ('deadline', 'status')

    fieldsets = (
        ('Subtask Information', {
            'fields': (
                'title',
                'description',
                'task',
                'assigned_to',
                'status',
                'deadline',
                'is_completed',
            )
        }),
        ('Timer Details', {
            'fields': (
                'start_time',
                'end_time',
                'time_spent_seconds',
            )
        }),
    )

    readonly_fields = ('time_spent_seconds',)
