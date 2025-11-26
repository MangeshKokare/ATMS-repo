# accounts/views.py

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from .forms import AdminRegisterForm, HODRegisterForm, StaffRegisterForm, UserCreationForm, SubTaskForm
from .models import CustomUser
from django.contrib import messages
from .forms import AddStaffForm
from .forms import CSVUploadForm
from .models import UploadedFile
from .forms import TaskForm
from .models import CustomUser, Team, Task, Project
from django.db import models

from allauth.account.models import EmailAddress
from allauth.socialaccount.models import SocialAccount, SocialLogin, SocialApp
from accounts.models import Task
from accounts.forms import TaskForm
from django.utils import timezone
from django.contrib.auth import logout
from .models import Event  
from datetime import date, timedelta
from django.db.models import Prefetch
from django.http import HttpResponseForbidden
from django.db.models import Q
from django.contrib.auth import get_user_model

User = get_user_model()


def login_view(request):
    if request.user.is_authenticated:
        if request.user.role == 'admin':
            return redirect('accounts:admin_dashboard')
        elif request.user.role == 'hod':
            return redirect('accounts:hod_dashboard')
        elif request.user.role == 'coordinator':      # ✅ NEW
            return redirect('accounts:coordinator_dashboard')
        elif request.user.role == 'staff':
            return redirect('accounts:staff_dashboard')
        elif request.user.role == 'student':
            return redirect('accounts:student_dashboard')
        else:
            return redirect('accounts:email_not_registered')

    if request.method == 'POST':
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            if not getattr(user, 'role', None):
                return redirect('accounts:email_not_registered')

            login(request, user)

            # Redirect based on user role
            if user.role == 'admin':
                return redirect('accounts:admin_dashboard')
            elif user.role == 'hod':
                return redirect('accounts:hod_dashboard')
            elif user.role == 'coordinator':       
                return redirect('accounts:coordinator_dashboard')
            elif user.role == 'staff':
                return redirect('accounts:staff_dashboard')
            elif user.role == 'student':
                return redirect('accounts:student_dashboard')
            else:
                return redirect('accounts:email_not_registered')

        else:
            messages.error(request, "Invalid credentials. Please try again.")
            return redirect('accounts:login')

    return render(request, 'accounts/login.html')




# Role-based dashboard view
@login_required
def dashboard(request):
    user = request.user

    # User exists but has no role
    if not user.role:
        return redirect('accounts:email_not_registered')

    if user.role == 'admin':
        return redirect('accounts:admin_dashboard')
    elif user.role == 'hod':
        return redirect('accounts:hod_dashboard')
    elif user.role == 'coordinator':      # ✅ ADDED
        return redirect('accounts:coordinator_dashboard')
    elif user.role == 'staff':
        return redirect('accounts:staff_dashboard')
    elif user.role == 'student':
        return redirect('accounts:student_dashboard')
    else:
        return redirect('accounts:email_not_registered')




# Admin Registration View for HOD
@login_required
def admin_register(request):
    if request.user.role == 'admin':  # Only admin can register HOD users
        if request.method == 'POST':
            form = UserCreationForm(request.POST)
            if form.is_valid():
                user = form.save(commit=False)
                user.role = 'hod'  # Admin registers as HOD
                user.save()
                return redirect('accounts:hod_dashboard')  # Redirect to HOD dashboard
        else:
            form = UserCreationForm()

        return render(request, 'accounts/register_admin.html', {'form': form})
    else:
        raise PermissionDenied("You do not have permission to register HOD users.")


# HOD Registration View for Staff
@login_required
def hod_register(request):
    if request.user.role == 'hod':  # Only HOD can register staff users
        if request.method == 'POST':
            form = UserCreationForm(request.POST)
            if form.is_valid():
                user = form.save(commit=False)
                user.role = 'staff'  # HOD registers as Staff
                user.save()
                return redirect('accounts:staff_dashboard')  # Redirect to Staff dashboard
        else:
            form = UserCreationForm()

        return render(request, 'accounts/register_hod.html', {'form': form})
    else:
        raise PermissionDenied("You do not have permission to register Staff users.")


# Staff Registration View for Staff user (Only Admin can do this)
@login_required
def staff_register(request):
    if request.user.role == 'admin':  # Only admin can register staff
        if request.method == 'POST':
            form = UserCreationForm(request.POST)
            if form.is_valid():
                user = form.save(commit=False)
                user.role = 'staff'  # Admin registers as Staff
                user.save()
                return redirect('accounts:staff_dashboard')  # Redirect to Staff dashboard
        else:
            form = UserCreationForm()

        return render(request, 'accounts/register_staff.html', {'form': form})
    else:
        raise PermissionDenied("You do not have permission to register Staff users.")


# View for Admin dashboard



# View for Admin dashboard
@login_required
def admin_dashboard(request):
    if request.user.role != 'admin':
        return redirect('accounts:login')  # Only admin can access

    # Existing logic
    hod_users = CustomUser.objects.filter(role='hod')

    # ✅ Added counts for dashboard statistics
    total_campuses = Campus.objects.count()
    total_schools = School.objects.count()
    total_departments = Department.objects.count()
    total_users = CustomUser.objects.count()

    context = {
        'users': hod_users,  # keep existing
        'total_campuses': total_campuses,
        'total_schools': total_schools,
        'total_departments': total_departments,
        'total_users': total_users,
        'total_campuses': Campus.objects.count(),
        'total_schools': School.objects.count(),
        'total_departments': Department.objects.count(),
        'total_users': CustomUser.objects.count(),
        'campus_names': list(Campus.objects.values_list('name', flat=True)),
        'campus_school_counts': [campus.school_set.count() for campus in Campus.objects.all()],
        'school_names': list(School.objects.values_list('name', flat=True)),
        'school_department_counts': [school.department_set.count() for school in School.objects.all()],
    }

    return render(request, 'accounts/admin_dashboard.html', context)


def settings_page(request):
    return render(request, 'accounts/settings_page.html')
    
@login_required
def hod_dashboard(request):
    user = request.user
    if user.role != 'hod':
        return redirect('accounts:login')

    now = timezone.now()

    # -----------------------------
    # HOD-related entities
    # -----------------------------
    hod_departments = user.department.all()
    hod_schools = School.objects.filter(department__in=hod_departments).distinct()
    hod_campuses = Campus.objects.filter(school__in=hod_schools).distinct()
    
    staff_qs = CustomUser.objects.filter(role='staff', department__in=hod_departments).distinct()
    
    # -----------------------------
    # Projects for HOD
    # -----------------------------
    projects_qs = Project.objects.filter(
        Q(created_by=user) |
        Q(created_by__in=staff_qs) |
        Q(department__in=hod_departments)
    ).distinct().prefetch_related('teams__staff', 'teams__members')

    # -----------------------------
    # Current project selection
    # -----------------------------
    project_id = request.GET.get('project')
    current_project = None

    if request.GET.get("project") is not None:
        # store selection in session
        request.session["selected_project_id"] = request.GET.get("project")

    selected_project_id = request.GET.get("project") or request.session.get("selected_project_id")

    if selected_project_id and selected_project_id != "":
        current_project = projects_qs.filter(id=selected_project_id).first()

    # -----------------------------
    # Tasks related to HOD projects
    # -----------------------------
    tasks_qs = Task.objects.filter(
        Q(project__department__in=hod_departments) |
        Q(assigned_to__in=staff_qs) |
        Q(assigned_to__in=CustomUser.objects.filter(role='student', department__in=hod_departments)) |
        Q(assigned_by=user)
    ).distinct()

    if current_project:
        tasks_qs = tasks_qs.filter(project=current_project)

    # -----------------------------
    # Kanban tasks
    # -----------------------------
    kanban_tasks = {
        'to_do': tasks_qs.filter(status='to_do'),
        'in_progress': tasks_qs.filter(status='in_progress'),
        'in_review': tasks_qs.filter(status='in_review'),
        'done': tasks_qs.filter(status='done'),
    }

    # -----------------------------
    # Status overview counts
    # -----------------------------
    todo_count = kanban_tasks['to_do'].count()
    in_progress_count = kanban_tasks['in_progress'].count()
    in_review_count = kanban_tasks['in_review'].count()
    done_count = kanban_tasks['done'].count()
    completed_count = tasks_qs.filter(status='done', updated_at__gte=now-timedelta(days=7)).count()
    updated_count = tasks_qs.filter(updated_at__gte=now-timedelta(days=7)).count()
    created_count = tasks_qs.filter(created_at__gte=now-timedelta(days=7)).count()
    due_soon_count = tasks_qs.filter(due_date__lte=now+timedelta(days=7), status__in=['to_do','in_progress']).count()

    # -----------------------------
    # Staff & students for task assignment
    # -----------------------------
    staff = staff_qs
    students = CustomUser.objects.filter(role='student', department__in=hod_departments).distinct()
    staff_and_students = staff | students

    # -----------------------------
    # Teams for HOD
    # -----------------------------
    all_allowed_teams = Team.objects.filter(
        Q(project__in=projects_qs) |
        Q(members__department__in=hod_departments)
    ).distinct().prefetch_related(
        Prefetch("members", queryset=CustomUser.objects.filter(department__in=hod_departments).distinct())
    )

    # ---------- NEW FILTERING LOGIC ----------
    if current_project:
        teams = all_allowed_teams.filter(project=current_project)
    else:
        teams = all_allowed_teams   # ALL TEAMS (within HOD scope)
    # -----------------------------------------

    # -----------------------------
    # Recent activities
    # -----------------------------
    recent_activities = tasks_qs.order_by('-created_at')[:5]

    # -----------------------------
    # Context
    # -----------------------------
    context = {
        'staff_and_students': staff_and_students,
        'active_tab': 'summary',
        'kanban_tasks': kanban_tasks,
        'todo_count': todo_count,
        'in_progress_count': in_progress_count,
        'in_review_count': in_review_count,
        'done_count': done_count,
        'completed_count': completed_count,
        'updated_count': updated_count,
        'created_count': created_count,
        'due_soon_count': due_soon_count,
        'recent_activities': recent_activities,
        'projects': projects_qs,
        'teams': teams,
        'current_project': current_project,
        "total_staff": staff.count(),
        "total_projects": projects_qs.count(),
        "staff_by_campus": [{'campus': c, 'count': staff_qs.filter(campus=c).count()} for c in hod_campuses],
        "staff_by_department": [{'department': d, 'count': staff_qs.filter(department=d).count()} for d in hod_departments],



    }

    return render(request, "accounts/summary.html", context)


@login_required
def hod_staff(request):
    user = request.user

    # ----------------------------------------------------
    # HOD: Departments, Schools, Campuses
    # ----------------------------------------------------
    hod_departments = user.department.all()
    hod_schools = School.objects.filter(department__in=hod_departments).distinct()
    hod_campuses = Campus.objects.filter(school__in=hod_schools).distinct()

    # Staff under HOD's departments
    staff = CustomUser.objects.filter(
        role='staff',
        department__in=hod_departments
    ).distinct()

    # ----------------------------------------------------
    # ROLE-BASED PROJECT FILTERING
    # ----------------------------------------------------
    if user.role == 'hod':
        projects = Project.objects.filter(
            Q(created_by=user) |
            Q(created_by__in=staff) |
            Q(department__in=hod_departments)
        ).distinct()

        # ----------------------------------------------------
        # NEW REQUIREMENT:
        # SHOW ONLY TEAMS IN THE LOGGED-IN HOD's SCHOOL
        # ----------------------------------------------------
        teams = Team.objects.filter(
            project__department__school=user.school
        ).distinct().select_related("project", "head").prefetch_related("members")

    else:
        # STAFF: show only their own projects
        projects = Project.objects.filter(
            Q(tasks__assigned_to=user) | Q(created_by=user)
        ).distinct()

        teams = Team.objects.filter(
            project__in=projects
        ).distinct().select_related("project", "head").prefetch_related("members")

    # ----------------------------------------------------
    # HANDLE STAFF CREATION
    # ----------------------------------------------------
    if request.method == "POST":
        email = request.POST.get("email")
        username = request.POST.get("username")
        emp_id = request.POST.get("emp_id")
        phone_number = request.POST.get("phone_number")
        gender = request.POST.get("gender")
        campus_id = request.POST.get("campus")
        school_id = request.POST.get("school")
        dept_ids = request.POST.getlist("department")

        # Email must be unique
        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "This email already exists!")
            return redirect('accounts:hod_staff')

        # Create staff user
        new_staff = CustomUser.objects.create(
            email=email,
            username=email,
            emp_id=emp_id,
            phone_number=phone_number,
            gender=gender,
            role='staff',
            campus_id=campus_id,
            school_id=school_id,
        )

        # Only allow departments belonging to this HOD
        allowed_dept_ids = [str(d.id) for d in hod_departments]
        filtered_dept_ids = [int(did) for did in dept_ids if did in allowed_dept_ids]
        new_staff.department.set(filtered_dept_ids)
        new_staff.save()

        messages.success(request, "Staff created successfully!")
        return redirect('accounts:hod_staff')

    return render(request, "accounts/hod_staff.html", {
        "staff": staff,
        "campuses": hod_campuses,
        "schools": hod_schools,
        "departments": hod_departments,
        "projects": projects,
        "teams": teams,  # ⬅ ADDED TO CONTEXT
    })



@login_required
def edit_staff(request, staff_id):
    staff_user = get_object_or_404(CustomUser, id=staff_id)

    # Optionally: restrict editing to HOD's departments
    hod_user = request.user
    allowed_departments = Department.objects.filter(school__campus=hod_user.campus)
    if not staff_user.department.filter(id__in=allowed_departments).exists():
        messages.error(request, "You cannot edit this staff member.")
        return redirect('accounts:hod_staff')

    if request.method == 'POST':
        staff_user.username = request.POST.get('username')
        staff_user.email = request.POST.get('email')
        staff_user.emp_id = request.POST.get('emp_id')
        staff_user.phone_number = request.POST.get('phone_number')
        staff_user.gender = request.POST.get('gender')
        campus_id = request.POST.get('campus')
        school_id = request.POST.get('school')
        department_ids = request.POST.getlist('department')

        staff_user.campus = Campus.objects.filter(id=campus_id).first() if campus_id else None
        staff_user.school = School.objects.filter(id=school_id).first() if school_id else None
        staff_user.department.set(Department.objects.filter(id__in=department_ids))

        staff_user.save()
        messages.success(request, "Staff updated successfully.")
        return redirect('accounts:hod_staff')

    context = {
        'staff_user': staff_user,
        'campuses': Campus.objects.all(),
        'schools': School.objects.all(),
        'departments': Department.objects.all()
    }
    return render(request, 'accounts/edit_staff.html', context)

def update_staff(request, staff_id):
    # Use CustomUser instead of Staff
    staff_member = get_object_or_404(CustomUser, id=staff_id, role='staff')

    if request.method == "POST":
        staff_member.email = request.POST.get("email")
        staff_member.username = staff_member.email
        staff_member.emp_id = request.POST.get("emp_id")
        staff_member.phone_number = request.POST.get("phone_number")
        staff_member.gender = request.POST.get("gender")
        staff_member.campus_id = request.POST.get("campus")
        staff_member.school_id = request.POST.get("school")
        dept_ids = request.POST.getlist("department")
        staff_member.save()
        staff_member.department.set(dept_ids)
        messages.success(request, "Staff updated successfully!")
        return redirect('accounts:hod_staff')


def delete_staff(request, staff_id):
    staff_member = get_object_or_404(CustomUser, id=staff_id, role='staff')
    staff_member.delete()
    messages.success(request, "Staff deleted successfully!")
    return redirect('accounts:hod_staff')



import csv

@login_required
def upload_staff_csv(request):
    """
    Upload staff members from CSV file.
    Expected CSV columns: email, emp_id, phone_number, campus_name, school_name, department_names
    """
    if request.method == 'POST' and request.FILES.get('csv_file'):
        csv_file = request.FILES['csv_file']

        # Validate file type
        if not csv_file.name.endswith('.csv'):
            messages.error(request, 'Please upload a valid CSV file.')
            return redirect('accounts:hod_staff')

        # Validate file size (5MB limit)
        if csv_file.size > 5 * 1024 * 1024:
            messages.error(request, 'File size exceeds 5MB limit.')
            return redirect('accounts:hod_staff')

        try:
            # Decode the CSV file
            decoded_file = csv_file.read().decode('utf-8-sig').splitlines()  # utf-8-sig handles BOM
            reader = csv.DictReader(decoded_file)

            # Validate headers (case-insensitive)
            fieldnames_lower = [f.lower().strip() for f in reader.fieldnames]
            required_headers = ['email', 'emp_id', 'phone_number', 'campus_name', 'school_name', 'department_names']
            
            if not all(header in fieldnames_lower for header in required_headers):
                messages.error(
                    request, 
                    f'CSV must contain these columns: {", ".join(required_headers)}. Found: {", ".join(reader.fieldnames)}'
                )
                return redirect('accounts:hod_staff')

            success_count = 0
            error_count = 0
            error_details = []

            for row_number, row in enumerate(reader, start=2):  # Start at 2 (accounting for header)
                try:
                    # Extract fields (handle case variations)
                    email = row.get('email', row.get('Email', '')).strip()
                    emp_id = row.get('emp_id', row.get('Emp ID', row.get('emp id', ''))).strip()
                    phone_number = row.get('phone_number', row.get('Phone Number', row.get('phone', ''))).strip()
                    campus_name = row.get('campus_name', row.get('Campus', row.get('campus', ''))).strip()
                    school_name = row.get('school_name', row.get('School', row.get('school', ''))).strip()
                    department_names = row.get('department_names', row.get('Departments', row.get('departments', ''))).strip()

                    # Validate required fields
                    if not email:
                        raise ValueError("Email is required")
                    if not emp_id:
                        raise ValueError("Employee ID is required")
                    if not campus_name:
                        raise ValueError("Campus name is required")
                    if not school_name:
                        raise ValueError("School name is required")
                    if not department_names:
                        raise ValueError("At least one department is required")

                    # Validate email format
                    if '@' not in email:
                        raise ValueError(f"Invalid email format: {email}")

                    # Get or create Campus
                    campus, campus_created = Campus.objects.get_or_create(name=campus_name)
                    if campus_created:
                        print(f"Created new campus: {campus_name}")

                    # Get or create School
                    school, school_created = School.objects.get_or_create(
                        name=school_name,
                        campus=campus
                    )
                    if school_created:
                        print(f"Created new school: {school_name}")

                    # Create or update staff user
                    user, user_created = CustomUser.objects.update_or_create(
                        email=email,
                        defaults={
                            'username': email.split('@')[0],  # Use email prefix as username
                            'emp_id': emp_id,
                            'phone_number': phone_number,
                            'phone_no': phone_number,  # You have both fields, set both
                            'campus': campus,
                            'school': school,
                            'role': 'staff',
                            'is_active': True,
                            'is_staff': False,  # is_staff is for Django admin access
                        }
                    )

                    # Set default password for newly created users only
                    if user_created:
                        user.set_password('Default123!')
                        user.save()
                        print(f"Created new user: {email}")
                    else:
                        print(f"Updated existing user: {email}")

                    # Handle multiple departments (separated by semicolon or comma)
                    # Support both ; and , as separators
                    department_names = department_names.replace(';', ',')
                    department_list = [d.strip() for d in department_names.split(',') if d.strip()]
                    
                    if not department_list:
                        raise ValueError("No valid department names found")

                    departments = []
                    for dept_name in department_list:
                        # Get or create department
                        department, dept_created = Department.objects.get_or_create(
                            name=dept_name,
                            school=school,
                            campus=campus
                        )
                        if dept_created:
                            print(f"Created new department: {dept_name}")
                        departments.append(department)

                    # Set departments (ManyToMany relationship)
                    user.department.set(departments)
                    print(f"Set {len(departments)} department(s) for user {email}")

                    success_count += 1

                except Exception as row_error:
                    error_count += 1
                    error_msg = f"Row {row_number} ({row.get('email', 'unknown')}): {str(row_error)}"
                    error_details.append(error_msg)
                    print(f"❌ Error processing row {row_number}: {row_error}")
                    import traceback
                    traceback.print_exc()

            # Display results
            if success_count > 0:
                messages.success(
                    request, 
                    f'✅ Successfully imported {success_count} staff member(s).'
                )

            if error_count > 0:
                # Limit error messages to first 5 to avoid overwhelming the UI
                displayed_errors = error_details[:5]
                error_message = f'❌ Failed to import {error_count} row(s). '
                if len(error_details) > 5:
                    error_message += f'First 5 errors: {"; ".join(displayed_errors)}... and {len(error_details) - 5} more.'
                else:
                    error_message += f'Errors: {"; ".join(displayed_errors)}'
                
                messages.error(request, error_message)

            if success_count == 0 and error_count == 0:
                messages.warning(request, 'No valid data found in CSV file.')

        except UnicodeDecodeError as e:
            messages.error(request, f'Unable to read CSV file. Please ensure it is UTF-8 encoded. Error: {str(e)}')
            print(f"UnicodeDecodeError: {e}")
        except Exception as e:
            messages.error(request, f'Error processing CSV file: {str(e)}')
            print(f"❌ CSV Upload Error: {str(e)}")
            import traceback
            traceback.print_exc()

    else:
        messages.error(request, 'No file uploaded or invalid request.')

    return redirect('accounts:hod_staff')


@login_required
def download_staff_csv_template(request):
    """
    Generate a CSV template for uploading staff.
    Includes sample data based on current user's campus/school/departments.
    """
    user = request.user

    # Ensure only HODs can access this feature
    if user.role != 'hod':
        messages.error(request, "You are not authorized to download this template.")
        return redirect('accounts:hod_staff')

    # Fetch related fields
    campus_name = user.campus.name if user.campus else 'Main Campus'
    school_name = user.school.name if user.school else 'Engineering'

    # Handle multiple departments (if HOD manages more than one)
    if user.department.exists():
        departments = user.department.all()
        department_names = ";".join([dept.name for dept in departments])
    else:
        department_names = 'Computer Science;Information Technology'

    # Prepare the response
    response = HttpResponse(content_type='text/csv')
    filename = f"staff_template_{user.username}.csv"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'

    writer = csv.writer(response)
    
    # Write header
    writer.writerow(['email', 'emp_id', 'phone_number', 'campus_name', 'school_name', 'department_names'])
    
    # Write sample rows
    writer.writerow([
        'staff1@example.com', 
        'EMP001', 
        '9876543210', 
        campus_name, 
        school_name, 
        department_names
    ])
    writer.writerow([
        'staff2@example.com', 
        'EMP002', 
        '9876543211', 
        campus_name, 
        school_name, 
        'Computer Science'  # Single department example
    ])

    return response



# -------------------------------
# Download CSV Template for Users
# -------------------------------
@login_required
def download_users_csv_template(request):
    """
    Generate a CSV template for uploading users.
    Format: Email | Emp ID | Phone | Campus | School | Departments
    Includes one sample row with random values
    """
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="users_upload_template.csv"'

    writer = csv.writer(response)

    # Header row
    writer.writerow([
        'Email',
        'Emp ID',
        'Phone',
        'Campus',
        'School',
        'Departments'  # Multiple departments separated by semicolon
    ])

    # Sample row
    writer.writerow([
        'mangesh.kokare@bds.christuniversity.in',
        '24352435',
        '43543543545',
        'Pune',
        'Law',
        'BALLB'
    ])

    return response


# -------------------------------
# Upload Users CSV
# -------------------------------
@login_required
def upload_users_csv(request):
    if request.method == "POST" and request.FILES.get('csv_file'):
        csv_file = request.FILES['csv_file']

        try:
            decoded_file = csv_file.read().decode('utf-8').splitlines()
            reader = csv.DictReader(decoded_file)

            created_count = 0
            error_count = 0

            for row_number, row in enumerate(reader, start=2):
                try:
                    email = row.get('Email', '').strip()
                    emp_id = row.get('Emp ID', '').strip()
                    phone = row.get('Phone', '').strip()
                    campus_name = row.get('Campus', '').strip()
                    school_name = row.get('School', '').strip()
                    dept_names = row.get('Departments', '').strip()

                    if not email or not emp_id:
                        raise ValueError(f"Missing email or emp_id at row {row_number}")

                    # Get or create campus & school by name
                    campus = Campus.objects.get_or_create(name=campus_name)[0] if campus_name else None
                    school = School.objects.get_or_create(name=school_name, campus=campus)[0] if school_name else None

                    # Create or update user
                    user, created = CustomUser.objects.update_or_create(
                        email=email,
                        defaults={
                            'username': email,
                            'emp_id': emp_id,
                            'phone_number': phone,
                            'campus': campus,
                            'school': school,
                            'is_staff': True,
                        }
                    )

                    # Handle departments
                    departments = []
                    if dept_names:
                        for dept_name in dept_names.split(','):
                            dept_name = dept_name.strip()
                            if dept_name:
                                department, _ = Department.objects.get_or_create(name=dept_name, school=school)
                                departments.append(department)
                    user.department.set(departments)

                    created_count += 1

                except Exception as e:
                    error_count += 1
                    print(f"Error processing row {row_number}: {row} - {e}")

            messages.success(
                request,
                f"CSV upload complete: {created_count} users added/updated, {error_count} rows failed."
            )

        except Exception as e:
            messages.error(request, f"Failed to process CSV file: {e}")

        # Redirect to create_user page
        return redirect('/accounts/create_user/')

    messages.error(request, "No file uploaded or invalid request.")
    return redirect('/accounts/create_user/')



@login_required
def hod_projects(request):
    hod_user = request.user

    # HOD-related departments
    hod_departments = hod_user.department.all()

    # Staff related to HOD
    staff_qs = CustomUser.objects.filter(role='staff', department__in=hod_departments).distinct()

    # Handle POST request to add new project + task
    if request.method == 'POST':
        project_name = request.POST.get('project_name')
        task_name = request.POST.get('task_name')
        deadline = request.POST.get('deadline')
        campus_id = request.POST.get('campus')
        school_id = request.POST.get('school')
        department_id = request.POST.get('department')
        assigned_staff_id = request.POST.get('assigned_staff')
        status = request.POST.get('status')

        try:
            department_obj = Department.objects.get(id=department_id)
            assigned_staff = CustomUser.objects.get(id=assigned_staff_id)

            # Create project
            project = Project.objects.create(
                name=project_name,
                department=department_obj,
                created_by=hod_user
            )

            # Create task
            Task.objects.create(
                title=task_name,
                assigned_to=assigned_staff,
                assigned_by=hod_user,
                project=project,
                due_date=deadline,
                status=status
            )

            messages.success(request, "Project and task added successfully!")
            return redirect('accounts:hod_projects')

        except Exception as e:
            messages.error(request, f"Error adding project/task: {str(e)}")
            # continue to render the page with context

    # Projects related to HOD departments OR tasks assigned to HOD staff
    projects = Project.objects.filter(
        Q(department__in=hod_departments) |
        Q(tasks__assigned_to__in=staff_qs)
    ).distinct()

    # HOD-related schools and campuses
    hod_schools = School.objects.filter(department__in=hod_departments).distinct()
    hod_campuses = Campus.objects.filter(school__in=hod_schools).distinct()

    context = {
        "campuses": hod_campuses,
        "schools": hod_schools,
        "departments": hod_departments,
        "staff": staff_qs,
        "projects": projects,
    }

    return render(request, "accounts/hod_project.html", context)

def delete_project(request, project_id):
    project = get_object_or_404(Project, id=project_id)
    project.delete()
    messages.success(request, f"Project '{project.name}' deleted successfully.")
    return redirect(request.META.get("HTTP_REFERER", "accounts:hod_dashboard"))


@login_required
def edit_project(request, project_id):
    project = get_object_or_404(Project, id=project_id)
    
    if request.method == "POST":
        project_name = request.POST.get("name")
        project_description = request.POST.get("description")
        project_keyword = request.POST.get("keyword", "").strip()

        # NEW → get dates
        start_date = request.POST.get("start_date") or None
        end_date = request.POST.get("end_date") or None

        if not project_name or not project_name.strip():
            messages.error(request, "Project name is required.")
            return redirect(request.META.get('HTTP_REFERER', 'accounts:hod_dashboard'))

        project.name = project_name.strip()
        project.description = project_description.strip() if project_description else ""
        project.keyword = project_keyword

        # NEW → save dates
        project.start_date = start_date
        project.end_date = end_date

        project.save()

        messages.success(request, "Project updated successfully.")
        return redirect(request.META.get('HTTP_REFERER', 'accounts:hod_dashboard'))
    
    return redirect('accounts:hod_dashboard')




@login_required
def edit_task(request, task_id):
    task = get_object_or_404(Task, id=task_id)
    staff = CustomUser.objects.filter(role='staff')  # staff list for selection
    if request.method == "POST":
        task.title = request.POST.get("task_name")
        task.description = request.POST.get("task_description")
        task.due_date = request.POST.get("deadline")
        task.status = request.POST.get("status")
        assigned_staff_id = request.POST.get("assigned_staff")
        if assigned_staff_id:
            task.assigned_to = CustomUser.objects.get(id=assigned_staff_id)
        task.save()
        messages.success(request, "Task updated successfully.")
        return redirect("accounts:hod_projects")

    context = {
        "task": task,
        "staff": staff
    }
    return render(request, "accounts/edit_task.html", context)

@login_required
def delete_task(request, task_id):
    """Delete a task"""
    task = get_object_or_404(Task, id=task_id)
    
    # Check permissions
    if request.user.role == 'coordinator':
        messages.error(request, 'Coordinators cannot delete tasks')
        return redirect(request.META.get('HTTP_REFERER', 'accounts:board_page'))
    
    if request.user.role == 'staff' and task.assigned_by != request.user:
        messages.error(request, 'You can only delete tasks you created')
        return redirect(request.META.get('HTTP_REFERER', 'accounts:board_page'))
    
    task.delete()
    messages.success(request, 'Task deleted successfully!')
    
    return redirect(request.META.get('HTTP_REFERER', 'accounts:board_page'))


@login_required
def duplicate_task(request, task_id):
    """Duplicate a task"""
    original_task = get_object_or_404(Task, id=task_id)
    
    # Check permissions
    if request.user.role == 'coordinator':
        messages.error(request, 'Coordinators cannot duplicate tasks')
        return redirect(request.META.get('HTTP_REFERER', 'accounts:board_page'))
    
    # Create duplicate
    new_task = Task.objects.create(
        title=f"{original_task.title} (Copy)",
        description=original_task.description,
        priority=original_task.priority,
        status='to_do',
        due_date=original_task.due_date,
        assigned_to=original_task.assigned_to,
        assigned_by=request.user,
        project=original_task.project,
        team=original_task.team,
    )
    
    # Duplicate subtasks
    for subtask in original_task.subtask_set.all():
        SubTask.objects.create(
            task=new_task,
            title=subtask.title,
            description=subtask.description,
            deadline=subtask.deadline,
            status='todo',
        )
    
    messages.success(request, f'Task duplicated successfully! New task: {new_task.title}')
    
    return redirect(request.META.get('HTTP_REFERER', 'accounts:board_page'))

@login_required
def hod_add_project(request):
    staff = CustomUser.objects.filter(role='staff')
    projects = Project.objects.all()

    if request.method == "POST":
        # Get POST data
        project_id = request.POST.get("project_select")  # Optional existing project
        project_name = request.POST.get("project_name")  # New project name if creating new
        task_title = request.POST.get("task_name")
        assigned_staff_id = request.POST.get("assigned_staff")
        due_date = request.POST.get("deadline")
        status = request.POST.get("status")

        # Use existing project or create new
        if project_id:
            project = Project.objects.get(id=project_id)
        else:
            project = Project.objects.create(
                name=project_name,
                created_by=request.user
            )

        assigned_staff = CustomUser.objects.get(id=assigned_staff_id)

        # Create Task using correct fields
        Task.objects.create(
            title=task_title,
            assigned_to=assigned_staff,
            assigned_by=request.user,
            project=project,
            due_date=due_date,
            status=status
        )

        messages.success(request, "Task added successfully.")
        return redirect("accounts:hod_projects")

    context = {
        "staff": staff,
        "projects": projects,
    }
    return render(request, "accounts/hod_project.html", context)


def hod_teams(request):
    return render(request, 'hod_teams.html', {})

def update_task(request, task_id):
    task = get_object_or_404(Task, id=task_id)

    if request.method == "POST":
        # Update task fields
        task.title = request.POST.get("task_name")
        task.description = request.POST.get("task_description", task.description)
        task.due_date = request.POST.get("deadline")
        task.status = request.POST.get("status")
        assigned_staff_id = request.POST.get("assigned_staff")
        if assigned_staff_id:
            task.assigned_to = CustomUser.objects.get(id=assigned_staff_id)
        task.save()
        messages.success(request, "Task updated successfully!")
        return redirect("accounts:hod_projects")
    

           
# ---------------- MANAGE STAFF ----------------
@login_required
def manage_staff(request):
    if not hasattr(request.user, "role") or request.user.role != 'hod':
        return redirect('accounts:login')
    
    staff_list = CustomUser.objects.filter(role='staff')
    campuses = Campus.objects.all()
    schools = School.objects.all()
    departments = Department.objects.all()
    
    return render(request, 'accounts/manage_staff.html', {
        'staff_list': staff_list,
        'campuses': campuses,
        'schools': schools,
        'departments': departments
    })

# ---------------- CREATE STAFF ----------------
@login_required
def hod_create_staff(request):
    if not hasattr(request.user, "role") or request.user.role != 'hod':
        return redirect('accounts:login')
    
    if request.method == 'POST':
        email = request.POST.get('email')
        username = email.split('@')[0]  # auto-generate username
        emp_id = request.POST.get('emp_id')
        phone_number = request.POST.get('phone_number')
        gender = request.POST.get('gender')
        campus_id = request.POST.get('campus')
        school_id = request.POST.get('school')
        department_id = request.POST.get('department')
        
        # Get related objects
        campus = Campus.objects.get(id=campus_id) if campus_id else None
        school = School.objects.get(id=school_id) if school_id else None
        department = Department.objects.get(id=department_id) if department_id else None
        
        # Create staff user
        staff = CustomUser.objects.create_user(
            username=username,
            email=email,
            role='staff',
            emp_id=emp_id,
            phone_number=phone_number,
            gender=gender,
            campus=campus,
            school=school,
            password='defaultpassword123'
        )

        # Assign department using .set() (if it's a ManyToManyField)
        if department:
            staff.department.set([department])  # Use set() for ManyToManyField

        messages.success(request, f'Staff {email} created successfully!')
        return redirect('accounts:manage_staff')
    
    campuses = Campus.objects.all()
    schools = School.objects.all()
    departments = Department.objects.all()
    
    return render(request, 'accounts/hod_create_staff.html', {
        'campuses': campuses,
        'schools': schools,
        'departments': departments
    })

# ---------------- UPDATE STAFF ----------------
@login_required
def hod_update_staff(request, staff_id):
    # Check if the user is 'hod'
    if not hasattr(request.user, "role") or request.user.role != 'hod':
        return redirect('accounts:login')

    # Get the staff instance
    staff = CustomUser.objects.get(id=staff_id)

    if request.method == 'POST':
        email = request.POST.get('email')
        emp_id = request.POST.get('emp_id')
        phone_number = request.POST.get('phone_number')
        gender = request.POST.get('gender')
        campus_id = request.POST.get('campus')
        school_id = request.POST.get('school')
        department_ids = request.POST.getlist('department')  # Use getlist() for multiple departments

        # Fetch the related objects (Campus, School, Department)
        campus = Campus.objects.get(id=campus_id) if campus_id else None
        school = School.objects.get(id=school_id) if school_id else None
        departments = Department.objects.filter(id__in=department_ids)  # Get departments by ID

        # Update the staff user
        staff.email = email
        staff.emp_id = emp_id
        staff.phone_number = phone_number
        staff.gender = gender
        staff.campus = campus
        staff.school = school
        staff.save()

        # Use .set() to assign multiple departments
        if departments.exists():
            staff.department.set(departments)  # This updates the many-to-many relationship

        messages.success(request, f'Staff {email} updated successfully!')
        return redirect('accounts:manage_staff')

    # Pre-fill the form with existing data
    campuses = Campus.objects.all()
    schools = School.objects.all()
    departments = Department.objects.all()

    return render(request, 'accounts/hod_update_staff.html', {
        'staff': staff,
        'campuses': campuses,
        'schools': schools,
        'departments': departments,
    })


# ---------------- DELETE STAFF ----------------
@login_required
def hod_delete_staff(request, staff_id):
    if request.user.role != 'hod':
        return HttpResponseForbidden("You are not authorized to perform this action.")
    
    staff = get_object_or_404(CustomUser, id=staff_id, role='staff')
    email = staff.email
    staff.delete()
    messages.success(request, f'{email} deleted successfully!')
    return redirect('accounts:manage_staff')

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def update_subtask_time(request, subtask_id):
    if request.method == 'POST':
        data = json.loads(request.body)
        elapsed_seconds = data.get('time_spent', 0)
        subtask = SubTask.objects.get(id=subtask_id)

        # Save total_time_seconds
        if hasattr(subtask, 'total_time_seconds'):
            subtask.total_time_seconds += elapsed_seconds
        else:
            subtask.total_time_seconds = elapsed_seconds

        # Optional: save total_time as timedelta
        from datetime import timedelta
        if hasattr(subtask, 'total_time'):
            subtask.total_time += timedelta(seconds=elapsed_seconds)
        else:
            subtask.total_time = timedelta(seconds=elapsed_seconds)

        subtask.save()
        return JsonResponse({'status': 'success', 'total_time_seconds': subtask.total_time_seconds})
    return JsonResponse({'status': 'fail'})

@login_required 
def staff_dashboard(request):
    if request.user.role != 'staff':
        return redirect('accounts:login')

    user = request.user
    user_departments = user.department.all()

    # -----------------------------
    # Task creation form handling
    # -----------------------------
    if request.method == 'POST' and 'create_task' in request.POST:
        task_form = TaskForm(request.POST)
        if task_form.is_valid():
            task = task_form.save(commit=False)
            task.assigned_by = request.user
            task.save()
            messages.success(request, "Task created successfully!")
            return redirect('accounts:staff_dashboard')
        else:
            messages.error(request, "There was an error creating the task.")
    else:
        task_form = TaskForm()

    # -----------------------------
    # Fetch projects where staff belongs to the department or is assigned/creator
    # -----------------------------
    projects = Project.objects.filter(
        Q(department__in=user_departments) | 
        Q(tasks__assigned_to=user) | 
        Q(created_by=user)
    ).distinct().prefetch_related('teams__staff', 'teams__members')

    # -----------------------------
    # Current project selection (persist in session)
    # -----------------------------
    if request.GET.get("project") is not None:
        request.session["selected_project_id"] = request.GET.get("project")

    selected_project_id = request.GET.get("project") or request.session.get("selected_project_id")

    current_project = None
    if selected_project_id and selected_project_id != "":
        current_project = projects.filter(id=selected_project_id).first()

    # -----------------------------
    # ALL TASKS: Both assigned to staff AND created by staff
    # -----------------------------
    if current_project:
        all_tasks = Task.objects.filter(
            Q(project=current_project) &
            (Q(assigned_to=user) | Q(assigned_by=user))
        )
    else:
        all_tasks = Task.objects.filter(
            Q(project__in=projects) &
            (Q(assigned_to=user) | Q(assigned_by=user))
        )
    
    all_tasks = all_tasks.distinct().order_by('-created_at')

    # -----------------------------
    # Kanban organization (ALL tasks)
    # -----------------------------
    kanban_tasks = {
        'to_do': all_tasks.filter(status='to_do'),
        'in_progress': all_tasks.filter(status='in_progress'),
        'in_review': all_tasks.filter(status='in_review'),
        'done': all_tasks.filter(status='done'),
    }

    # -----------------------------
    # Status overview counts
    # -----------------------------
    todo_count = kanban_tasks['to_do'].count()
    in_progress_count = kanban_tasks['in_progress'].count()
    in_review_count = kanban_tasks['in_review'].count()
    done_count = kanban_tasks['done'].count()
    completed_count = all_tasks.filter(
        status='done', 
        updated_at__gte=timezone.now()-timedelta(days=7)
    ).count()
    updated_count = all_tasks.filter(
        updated_at__gte=timezone.now()-timedelta(days=7)
    ).count()
    created_count = all_tasks.filter(
        created_at__gte=timezone.now()-timedelta(days=7)
    ).count()

    # Only count due soon for tasks assigned TO the user
    due_soon_count = all_tasks.filter(
        assigned_to=user,
        due_date__lte=timezone.now()+timedelta(days=7), 
        status__in=['to_do','in_progress']
    ).count()

    # -----------------------------
    # Users in the same department (distinct)
    # -----------------------------
    staff_and_students = CustomUser.objects.filter(
        role='staff',
        department__in=user_departments
    ).distinct()

    # -----------------------------
    # Teams (Allowed teams only)
    # -----------------------------
    all_allowed_teams = Team.objects.filter(
        Q(project__in=projects) |
        Q(members__department__in=user_departments)
    ).distinct().prefetch_related(
        Prefetch("members", queryset=CustomUser.objects.filter(department__in=user_departments).distinct())
    )

    # ---------- NEW FILTERING LOGIC ----------
    if current_project:
        teams = all_allowed_teams.filter(project=current_project)
    else:
        teams = all_allowed_teams    # ALL allowed teams
    # -----------------------------------------

    # -----------------------------
    # Recent activities
    # -----------------------------
    recent_activities = all_tasks[:5]

    # -----------------------------
    # Context
    # -----------------------------
    context = {
        'staff_and_students': staff_and_students,
        'active_tab': 'summary',
        'task_form': task_form,
        'kanban_tasks': kanban_tasks,
        'todo_count': todo_count,
        'in_progress_count': in_progress_count,
        'in_review_count': in_review_count,
        'done_count': done_count,
        'completed_count': completed_count,
        'updated_count': updated_count,
        'created_count': created_count,
        'due_soon_count': due_soon_count,
        'recent_activities': recent_activities,
        'projects': projects,
        'teams': teams,
        'current_project': current_project,
        'is_staff_view': True,
        'current_user': user,
    }

    return render(request, 'accounts/summary.html', context)



@login_required
def delete_team(request, team_id):
    team = get_object_or_404(Team, id=team_id)
    team.delete()
    messages.success(request, f"Team '{team.name}' deleted successfully.")
    return redirect(request.META.get("HTTP_REFERER", "accounts:staff_dashboard"))



@login_required
def create_project(request):
    user = request.user

    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')
        keyword = request.POST.get('keyword', '').strip()
        start_date = request.POST.get('start_date') or None
        end_date = request.POST.get('end_date') or None

        if not name:
            messages.error(request, "Project name is required.")
            return redirect(request.META.get('HTTP_REFERER', '/'))

        # Create project
        project = Project.objects.create(
            name=name,
            description=description,
            keyword=keyword,
            created_by=user,
            created_at=timezone.now(),
            start_date=start_date,
            end_date=end_date
        )

        # 🔥 AUTO-ASSIGN DEPARTMENTS BASED ON ROLE

        # -------------------------
        # 1️⃣ STAFF → Only their dept
        # -------------------------
        if user.role == "staff":
            staff_departments = user.department.all()
            if staff_departments.exists():
                project.department.set(staff_departments)
            else:
                messages.error(request, "Staff has no department assigned.")

        # -------------------------
        # 2️⃣ HOD → All their departments
        # -------------------------
        elif user.role == "hod":
            hod_departments = user.department.all()
            if hod_departments.exists():
                project.department.set(hod_departments)
            else:
                messages.error(request, "HOD has no department assigned.")

        # -------------------------
        # 3️⃣ COORDINATOR → Read-only (should NOT create project)
        # -------------------------
        elif user.role == "coordinator":
            messages.error(request, "Coordinator cannot create projects.")
            project.delete()
            return redirect('accounts:coordinator_dashboard')

        project.save()

        # Redirect based on role
        if user.role == "hod":
            return redirect('accounts:hod_dashboard')
        else:
            return redirect('accounts:staff_dashboard')

    return render(request, 'accounts/create_project.html')


@login_required
def timeline_page(request):
    user = request.user

    # -----------------------------
    # Projects based on role
    # -----------------------------
    if user.role == 'hod':
        hod_departments = user.department.all()
        staff_qs = CustomUser.objects.filter(
            role='staff',
            department__in=hod_departments
        ).distinct()

        projects = Project.objects.filter(
            Q(created_by=user) |
            Q(created_by__in=staff_qs) |
            Q(department__in=hod_departments)
        ).distinct()

        # Users in HOD's departments (exclude HODs and Admins)
        staff_and_students = CustomUser.objects.filter(
            department__in=hod_departments
        ).exclude(Q(role='hod') | Q(role='admin') | Q(is_superuser=True)).distinct()

        # Teams in HOD's departments (exclude HODs and Admins)
        teams = Team.objects.filter(
            members__department__in=hod_departments
        ).distinct().prefetch_related(
            Prefetch(
                "members",
                queryset=CustomUser.objects.filter(
                    department__in=hod_departments
                ).exclude(Q(role='hod') | Q(role='admin') | Q(is_superuser=True)).distinct()
            )
        )

    else:  # Staff
        user_departments = user.department.all()

        projects = Project.objects.filter(
            Q(tasks__assigned_to=user) |
            Q(created_by=user) |
            Q(department__in=user_departments)
        ).distinct()

        # Users in staff's departments (exclude HODs and Admins)
        staff_and_students = CustomUser.objects.filter(
            department__in=user_departments
        ).exclude(Q(role='hod') | Q(role='admin') | Q(is_superuser=True)).distinct()

        # Teams in staff's departments (exclude HODs and Admins)
        teams = Team.objects.filter(
            members__department__in=user_departments
        ).distinct().prefetch_related(
            Prefetch(
                "members",
                queryset=CustomUser.objects.filter(
                    department__in=user_departments
                ).exclude(Q(role='hod') | Q(role='admin') | Q(is_superuser=True)).distinct()
            )
        )

    # -----------------------------
    # Current project selection
    # -----------------------------
    selected_project_id = request.GET.get("project")
    current_project = get_object_or_404(projects, id=selected_project_id) if selected_project_id else None

    # -----------------------------
    # Tasks for selected project or all visible projects
    # -----------------------------
    if current_project:
        tasks = Task.objects.filter(project=current_project)
    else:
        tasks = Task.objects.filter(project__in=projects)

    # -----------------------------
    # Filters
    # -----------------------------
    query = request.GET.get("q", "").strip()
    sprint_filter = request.GET.get("sprint", "").strip()

    if query:
        tasks = tasks.filter(
            Q(title__icontains=query) |
            Q(due_date__icontains=query)
        )
    if sprint_filter:
        tasks = tasks.filter(sprint=sprint_filter)

    # -----------------------------
    # Tasks sorted by due date & distinct sprints
    # -----------------------------
    tasks_by_date = tasks.order_by("due_date")
    sprints = Task.objects.exclude(sprint__exact="").values_list("sprint", flat=True).distinct()

    # -----------------------------
    # Context
    # -----------------------------
    context = {
        "tasks": tasks_by_date,
        "teams": teams,
        "projects": projects,
        "current_project": current_project,
        "sprints": sprints,
        "query": query,
        "selected_sprint": sprint_filter,
        "active_tab": "timeline",
        "today": timezone.now().date(),
        "staff_and_students": staff_and_students,
    }

    return render(request, "accounts/timeline.html", context)



@login_required
def board_page(request):
    user = request.user

    # -----------------------------
    # PROJECTS BASED ON ROLE
    # -----------------------------
    if user.role == 'hod':
        hod_departments = user.department.all()
        staff_qs = CustomUser.objects.filter(
            role='staff', department__in=hod_departments
        ).distinct()

        projects = Project.objects.filter(
            Q(created_by=user) |
            Q(created_by__in=staff_qs) |
            Q(department__in=hod_departments)
        ).distinct()

        staff_and_students = CustomUser.objects.filter(
            department__in=hod_departments
        ).exclude(Q(role='hod') | Q(role='admin') | Q(is_superuser=True)).distinct()

        teams = Team.objects.filter(
            members__department__in=hod_departments
        ).distinct().prefetch_related(
            Prefetch(
                "members",
                queryset=CustomUser.objects.filter(
                    department__in=hod_departments
                ).exclude(Q(role='hod') | Q(role='admin') | Q(is_superuser=True)).distinct()
            )
        )

    elif user.role == 'coordinator':
        coordinator_campus = user.campus
        schools = School.objects.filter(campus=coordinator_campus)
        departments = Department.objects.filter(school__in=schools)

        campus_users = CustomUser.objects.filter(campus=coordinator_campus)

        projects = Project.objects.filter(
            Q(department__in=departments) |
            Q(created_by__in=campus_users) |
            Q(tasks__assigned_to__in=campus_users) |
            Q(teams__members__in=campus_users)
        ).distinct()

        staff_and_students = campus_users.exclude(
            Q(role='hod') | Q(role='admin') | Q(is_superuser=True)
        ).distinct()

        teams = Team.objects.filter(
            Q(project__in=projects) |
            Q(members__in=campus_users)
        ).distinct().prefetch_related(
            Prefetch("members", queryset=campus_users)
        )

    else:   # STAFF ROLE
        user_departments = user.department.all()

        projects = Project.objects.filter(
            Q(tasks__assigned_to=user) |
            Q(created_by=user) |
            Q(department__in=user_departments)
        ).distinct()

        staff_and_students = CustomUser.objects.filter(
            department__in=user_departments
        ).exclude(Q(role='hod') | Q(role='admin') | Q(is_superuser=True)).distinct()

        teams = Team.objects.filter(
            members__department__in=user_departments
        ).distinct()

    # -----------------------------
    # CURRENT PROJECT
    # -----------------------------
    project_id = request.GET.get('project')
    current_project = None
    if project_id:
        current_project = projects.filter(id=project_id).first()

    # -----------------------------
    # TASK FETCHING BASED ON ROLE
    # -----------------------------
    if user.role == 'coordinator':
        campus_users = CustomUser.objects.filter(campus=user.campus)
        tasks = Task.objects.filter(
            Q(project__in=projects) |
            Q(assigned_to__in=campus_users) |
            Q(team__members__in=campus_users)
        ).distinct()

        if current_project:
            tasks = tasks.filter(project=current_project)

    elif user.role == 'staff':
        # STAFF SPECIFIC VISIBILITY RULES
        if current_project:
            tasks = Task.objects.filter(
                Q(project=current_project) &
                (Q(assigned_to=user) | Q(assigned_by=user))
            )
        else:
            tasks = Task.objects.filter(
                Q(project__in=projects) &
                (Q(assigned_to=user) | Q(assigned_by=user))
            )

    else:  # HOD / ADMIN
        if current_project:
            tasks = Task.objects.filter(project=current_project)
        else:
            tasks = Task.objects.filter(project__in=projects)

    # -----------------------------
    # ANNOTATE TASKS WITH EXTRA DATA
    # -----------------------------
    tasks = tasks.annotate(
        completed_subtasks_count=Count(
            'subtask',
            filter=Q(subtask__status='done')
        ),
        total_subtasks_count=Count('subtask')
    ).select_related('assigned_to', 'team', 'project').prefetch_related(
        'subtask_set',
        'comment_set__user'
    )

    # -----------------------------
    # FILTERS
    # -----------------------------
    q = request.GET.get("q")
    status = request.GET.get("status")
    priority = request.GET.get("priority")

    if q:
        tasks = tasks.filter(title__icontains=q)
    if status:
        tasks = tasks.filter(status=status)
    if priority:
        tasks = tasks.filter(priority=priority)

    # -----------------------------
    # ADD COMPUTED PROPERTIES TO TASKS
    # -----------------------------
    today = timezone.now().date()
    tasks_list = []
    
    for task in tasks:
        # Calculate subtask completion percentage
        if task.total_subtasks_count > 0:
            task.subtask_completion_percentage = int(
                (task.completed_subtasks_count / task.total_subtasks_count) * 100
            )
        else:
            task.subtask_completion_percentage = 0
        
        # Check if task is overdue
        task.is_overdue = task.due_date < today if task.due_date else False
        
        # Attachment count (set to 0 if you don't have attachments yet)
        task.attachment_count = 0
        
        tasks_list.append(task)

    # -----------------------------
    # KANBAN COLUMNS (ALL 4 STATUSES)
    # -----------------------------
    kanban_tasks = {
        'to_do': [t for t in tasks_list if t.status == 'to_do'],
        'in_progress': [t for t in tasks_list if t.status == 'in_progress'],
        'in_review': [t for t in tasks_list if t.status == 'in_review'],
        'done': [t for t in tasks_list if t.status == 'done'],
    }

    # -----------------------------
    # CALCULATE HIGH PRIORITY COUNT
    # -----------------------------
    high_priority_count = sum(1 for t in tasks_list if t.priority == 'high')

    # -----------------------------
    # CONTEXT
    # -----------------------------
    context = {
        'projects': projects,
        'staff_and_students': staff_and_students,
        'teams': teams,
        'tasks': tasks_list,
        'kanban_tasks': kanban_tasks,
        'current_project': current_project,
        'active_tab': 'board',
        'high_priority_count': high_priority_count,
    }

    return render(request, 'accounts/board.html', context)




from django.views.decorators.http import require_POST
from .models import Project, Task, SubTask, Comment

@login_required
@require_POST
def add_subtask(request):
    task_id = request.POST.get('task_id')
    title = request.POST.get('title')
    deadline = request.POST.get('deadline')
    description = request.POST.get('description')

    task = get_object_or_404(Task, id=task_id)

    SubTask.objects.create(
        task=task,
        title=title,
        description=description,
        deadline=deadline if deadline else None
    )

    messages.success(request, 'Subtask added successfully!')
    return redirect(request.META.get('HTTP_REFERER', 'accounts:board_page'))

@login_required
@require_POST
def add_comment(request, task_id):
    task = get_object_or_404(Task, id=task_id)
    comment_text = request.POST.get('comment', '').strip()

    if comment_text:
        Comment.objects.create(
            task=task,
            user=request.user,
            text=comment_text   # DO NOT prepend text — template handles coordinator label
        )
        messages.success(request, 'Comment added successfully!')
    else:
        messages.error(request, 'Comment cannot be empty')

    return redirect(request.META.get('HTTP_REFERER', '/'))

@login_required
@require_POST
def edit_comment(request, comment_id):
    comment = get_object_or_404(Comment, id=comment_id, user=request.user)

    new_text = request.POST.get('comment', '').strip()

    if new_text:
        comment.text = new_text
        comment.save()
        messages.success(request, "Comment updated successfully.")
    else:
        messages.error(request, "Comment cannot be empty.")

    return redirect(request.META.get("HTTP_REFERER", "/"))


@login_required
def edit_subtask(request, pk):
    subtask = get_object_or_404(SubTask, pk=pk)

    if request.method == "POST":
        subtask.title = request.POST.get('title', subtask.title)
        subtask.description = request.POST.get('description', subtask.description)

        deadline_str = request.POST.get('deadline', '')
        if deadline_str:
            subtask.deadline = deadline_str  # Django will parse YYYY-MM-DD correctly
        else:
            subtask.deadline = None  # no date provided

        subtask.status = request.POST.get('status', subtask.status)
        subtask.save()

        messages.success(request, 'Subtask updated successfully!')
        return redirect(request.META.get('HTTP_REFERER', '/'))

    return redirect(request.META.get('HTTP_REFERER', '/'))


@login_required
def delete_subtask(request, pk):
    """Delete a subtask"""
    subtask = get_object_or_404(SubTask, pk=pk)
    
    # Check permissions
    if request.user.role == 'coordinator':
        messages.error(request, 'Coordinators cannot delete subtasks')
        return redirect(request.META.get('HTTP_REFERER', 'accounts:board_page'))
    
    subtask.delete()
    messages.success(request, 'Subtask deleted successfully!')
    
    return redirect(request.META.get('HTTP_REFERER', 'accounts:board_page'))
@login_required
def profile_view(request):
    user = request.user

    # --------------------------------------------------------
    # ROLE-BASED PROJECT FILTERING (same logic as other views)
    # --------------------------------------------------------
    if user.role == 'coordinator':
        projects = Project.objects.filter(
            department__campus=user.campus
        ).distinct()

        allowed_users = CustomUser.objects.filter(
            campus=user.campus,
            role__in=['staff', 'student']
        ).distinct()

    elif user.role == 'hod':
        hod_departments = user.department.all()

        projects = Project.objects.filter(
            department__school=user.school
        ).distinct()

        allowed_users = CustomUser.objects.filter(
            school=user.school,
            role__in=['staff', 'student']
        ).distinct()

    else:  # staff
        projects = Project.objects.filter(
            department__in=user.department.all()
        ).distinct()

        allowed_users = CustomUser.objects.filter(
            department__in=user.department.all(),
            role__in=['staff', 'student']
        ).distinct()

    # --------------------------------------------------------
    # CURRENT PROJECT SELECTION
    # --------------------------------------------------------
    project_id = request.GET.get('project')
    current_project = None

    if project_id:
        current_project = get_object_or_404(projects, id=project_id)

    # --------------------------------------------------------
    # TASKS: filter by current project or all visible projects
    # --------------------------------------------------------
    if current_project:
        tasks = Task.objects.filter(project=current_project)
    else:
        tasks = Task.objects.filter(project__in=projects)

    # --------------------------------------------------------
    # APPLY SEARCH + FILTERS
    # --------------------------------------------------------
    query = request.GET.get('q')
    status = request.GET.get('status')
    priority = request.GET.get('priority')
    team_filter = request.GET.get('team')

    if query:
        tasks = tasks.filter(title__icontains=query)

    if status:
        tasks = tasks.filter(status=status)

    if priority:
        tasks = tasks.filter(priority=priority)

    if team_filter:
        tasks = tasks.filter(team__id=team_filter)

    # --------------------------------------------------------
    # TEAMS: only teams connected to visible projects
    # --------------------------------------------------------
    teams = Team.objects.filter(
        project__in=projects
    ).select_related("project", "head").prefetch_related("members").distinct()

    # --------------------------------------------------------
    # CONTEXT
    # --------------------------------------------------------
    context = {
        'projects': projects,
        'tasks': tasks,
        'teams': teams,
        'current_project': current_project,
        'active_tab': 'backlog',
        'staff_and_students': allowed_users,   # UPDATED & FIXED
    }

    return render(request, "accounts/profile.html", context)


def settings_view(request):
    return render(request, "accounts/settings.html")

def logout_view(request):
    logout(request)
    return redirect("accounts:login")



from django.contrib import messages
from django.shortcuts import render, get_object_or_404, redirect
from .models import CustomUser, Team, Project, Task
@login_required
def create_task(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        assigned_to_id = request.POST.get('assigned_to')
        team_id = request.POST.get('team')
        project_id = request.POST.get('project')
        status = request.POST.get('status')
        priority = request.POST.get('priority')
        due_date = request.POST.get('due_date') or None

        if not assigned_to_id and not team_id:
            messages.error(request, 'You must assign this task to a user or a team.')
            return redirect('accounts:staff_dashboard')

        assigned_to = get_object_or_404(CustomUser, id=assigned_to_id) if assigned_to_id else None
        team = get_object_or_404(Team, id=team_id) if team_id else None
        project = get_object_or_404(Project, id=project_id) if project_id else None

        assigned_by = request.user

        # ---------------------------------------------------------
        # CASE 1 → Assigned to one User
        # ---------------------------------------------------------
        if assigned_to:
            Task.objects.create(
                title=title,
                description=description,
                assigned_to=assigned_to,
                team=team,
                project=project,
                assigned_by=assigned_by,
                status=status,
                priority=priority,
                due_date=due_date
            )

        # ---------------------------------------------------------
        # CASE 2 → Assigned to entire Team (INCLUDING TEAM HEAD)
        # ---------------------------------------------------------
        elif team:
            # Get all team members
            team_members = set(team.members.all())

            # Ensure team head is included
            if team.head:
                team_members.add(team.head)

            # Create individual task for each team member
            for member in team_members:
                Task.objects.create(
                    title=title,
                    description=description,
                    assigned_to=member,
                    team=team,
                    project=project,
                    assigned_by=assigned_by,
                    status=status,
                    priority=priority,
                    due_date=due_date
                )

        messages.success(request, 'Task created successfully!')
        return redirect('accounts:staff_dashboard')

    # --- GET REQUEST (Render form) ---
    logged_in_user = request.user
    staff_and_students = CustomUser.objects.filter(department__in=logged_in_user.department.all())

    teams = Team.objects.all()
    projects = Project.objects.all()

    return render(request, 'accounts/create_task_modal.html', {
        'staff_and_students': staff_and_students,
        'teams': teams,
        'projects': projects,
    })



@login_required
def board_page(request):
    user = request.user

    # -----------------------------
    # Projects based on role
    # -----------------------------
    if user.role == 'hod':
        hod_departments = user.department.all()
        staff_qs = CustomUser.objects.filter(
            role='staff', department__in=hod_departments
        ).distinct()

        # Projects
        projects = Project.objects.filter(
            Q(created_by=user) |
            Q(created_by__in=staff_qs) |
            Q(department__in=hod_departments)
        ).distinct()

        # Users in HOD's departments (exclude HODs and Admins)
        staff_and_students = CustomUser.objects.filter(
            department__in=hod_departments
        ).exclude(Q(role='hod') | Q(role='admin') | Q(is_superuser=True)).distinct()

        # Teams in HOD's departments (exclude HODs and Admins)
        teams = Team.objects.filter(
            members__department__in=hod_departments
        ).distinct().prefetch_related(
            Prefetch(
                "members",
                queryset=CustomUser.objects.filter(
                    department__in=hod_departments
                ).exclude(Q(role='hod') | Q(role='admin') | Q(is_superuser=True)).distinct()
            )
        )

    elif user.role == 'coordinator':
        # Coordinators see projects from their campus
        coordinator_campus = user.campus
        
        # Get schools and departments in coordinator's campus
        schools = School.objects.filter(campus=coordinator_campus)
        departments = Department.objects.filter(school__in=schools)
        
        # All users in this campus
        campus_users = CustomUser.objects.filter(campus=coordinator_campus)

        # Projects that belong to the coordinator's campus
        projects = Project.objects.filter(
            Q(department__in=departments) |                # Projects of departments in this campus
            Q(created_by__in=campus_users) |               # Projects created by any user in campus
            Q(tasks__assigned_to__in=campus_users) |       # Projects having tasks assigned to campus users
            Q(teams__members__in=campus_users)             # Projects having teams with campus users
        ).distinct()

        # Users in coordinator's campus (exclude HODs and Admins)
        staff_and_students = campus_users.exclude(
            Q(role='hod') | Q(role='admin') | Q(is_superuser=True)
        ).distinct()

        # Teams inside the coordinator's campus
        teams = Team.objects.filter(
            Q(project__in=projects) |                      # All teams assigned to campus projects
            Q(members__in=campus_users)                    # Teams consisting of campus users
        ).distinct().prefetch_related(
            Prefetch("members", queryset=campus_users)
        )

    else:  # Staff
        user_departments = user.department.all()

        # Projects: assigned to or created by the staff OR in their departments
        projects = Project.objects.filter(
            Q(tasks__assigned_to=user) |
            Q(created_by=user)
        ).distinct()


        # Users in staff's departments (exclude HODs and Admins)
        staff_and_students = CustomUser.objects.filter(
            department__in=user_departments
        ).exclude(Q(role='hod') | Q(role='admin') | Q(is_superuser=True)).distinct()

        # Teams in staff's departments (exclude HODs and Admins)
        teams = Team.objects.filter(
            members__department__in=user_departments
        ).distinct().prefetch_related(
            Prefetch(
                "members",
                queryset=CustomUser.objects.filter(
                    department__in=user_departments
                ).exclude(Q(role='hod') | Q(role='admin') | Q(is_superuser=True)).distinct()
            )
        )

    # -----------------------------
    # Current project selection
    # -----------------------------
    project_id = request.GET.get('project')
    current_project = None
    
    if project_id:
        current_project = projects.filter(id=project_id).first()

    # -----------------------------
    # Tasks for selected project or all visible projects
    # -----------------------------
    if user.role == 'coordinator':
        coordinator_campus = user.campus
        campus_users = CustomUser.objects.filter(campus=coordinator_campus)
        
        # Tasks inside coordinator's campus
        tasks = Task.objects.filter(
            Q(project__in=projects) |                   # All tasks from all campus projects
            Q(assigned_to__in=campus_users) |           # Tasks assigned to campus users
            Q(team__members__in=campus_users)           # Team-based tasks
        ).distinct()
        
        # If project selected → filter tasks of that project only
        if current_project:
            tasks = tasks.filter(project=current_project)
    else:
        if current_project:
            tasks = Task.objects.filter(project=current_project)
        else:
            tasks = Task.objects.filter(project__in=projects)

    # -----------------------------
    # Filters
    # -----------------------------
    query = request.GET.get('q')
    status = request.GET.get('status')
    priority = request.GET.get('priority')

    if query:
        tasks = tasks.filter(title__icontains=query)
    if status:
        tasks = tasks.filter(status=status)
    if priority:
        tasks = tasks.filter(priority=priority)

    # -----------------------------
    # Kanban columns
    # -----------------------------
    kanban_tasks = {
        'to_do': tasks.filter(status='to_do'),
        'in_progress': tasks.filter(status='in_progress'),
        'in_review': tasks.filter(status='in_review'),
        'done': tasks.filter(status='done'),
    }

    # -----------------------------
    # Context
    # -----------------------------
    context = {
        'projects': projects,
        'staff_and_students': staff_and_students,
        'teams': teams,
        'tasks': tasks,
        'kanban_tasks': kanban_tasks,
        'current_project': current_project,
        'active_tab': 'board',
    }

    return render(request, 'accounts/board.html', context)

@login_required
def backlog_page(request):
    user = request.user
    user_departments = user.department.all()

    # -----------------------------
    # PROJECTS BASED ON ROLE
    # -----------------------------
    if user.role == 'hod':
        hod_departments = user.department.all()
        staff_qs = CustomUser.objects.filter(
            role='staff',
            department__in=hod_departments
        ).distinct()

        projects = Project.objects.filter(
            Q(created_by=user) |
            Q(created_by__in=staff_qs) |
            Q(department__in=hod_departments)
        ).distinct()

        staff_and_students = CustomUser.objects.filter(
            department__in=hod_departments
        ).exclude(
            Q(role='hod') | Q(role='admin') | Q(is_superuser=True)
        ).distinct()

        teams = Team.objects.filter(
            members__department__in=hod_departments
        ).distinct().prefetch_related(
            Prefetch(
                "members",
                queryset=CustomUser.objects.filter(
                    department__in=hod_departments
                ).exclude(
                    Q(role='hod') | Q(role='admin') | Q(is_superuser=True)
                ).distinct()
            )
        )

    elif user.role == 'coordinator':
        coordinator_campus = user.campus
        schools = School.objects.filter(campus=coordinator_campus)
        departments = Department.objects.filter(school__in=schools)
        campus_users = CustomUser.objects.filter(campus=coordinator_campus)

        projects = Project.objects.filter(
            Q(department__in=departments) |
            Q(created_by__in=campus_users) |
            Q(tasks__assigned_to__in=campus_users) |
            Q(teams__members__in=campus_users)
        ).distinct()

        staff_and_students = campus_users.exclude(
            Q(role='hod') | Q(role='admin') | Q(is_superuser=True)
        ).distinct()

        teams = Team.objects.filter(
            Q(project__in=projects) |
            Q(members__in=campus_users)
        ).distinct().prefetch_related(
            Prefetch("members", queryset=campus_users)
        )

    else:  # Staff
        projects = Project.objects.filter(
            Q(tasks__assigned_to=user) |
            Q(created_by=user)
        ).distinct()


        staff_and_students = CustomUser.objects.filter(
            department__in=user_departments
        ).exclude(
            Q(role='hod') | Q(role='admin') | Q(is_superuser=True)
        ).distinct()

        teams = Team.objects.filter(
            members__department__in=user_departments
        ).distinct().prefetch_related(
            Prefetch(
                "members",
                queryset=CustomUser.objects.filter(
                    department__in=user_departments
                ).exclude(
                    Q(role='hod') | Q(role='admin') | Q(is_superuser=True)
                ).distinct()
            )
        )

    # -----------------------------
    # CURRENT PROJECT HANDLING
    # -----------------------------
    project_id = request.GET.get('project')
    current_project = None
    if project_id:
        current_project = projects.filter(id=project_id).first()

    # -----------------------------
    # TASK FETCHING (ROLE-BASED)
    # -----------------------------
    if user.role == 'coordinator':
        campus_users = CustomUser.objects.filter(campus=user.campus)

        tasks = Task.objects.filter(
            Q(project__in=projects) |
            Q(assigned_to__in=campus_users) |
            Q(team__members__in=campus_users)
        ).distinct()

        if current_project:
            tasks = tasks.filter(project=current_project)

    elif user.role == 'staff':
        # ✔ Staff must ONLY see:
        #   1. Tasks assigned to them
        #   2. Tasks created by them
        if current_project:
            tasks = Task.objects.filter(
                Q(project=current_project) &
                (Q(assigned_to=user) | Q(assigned_by=user))
            ).distinct()
        else:
            tasks = Task.objects.filter(
                Q(project__in=projects) &
                (Q(assigned_to=user) | Q(assigned_by=user))
            ).distinct()

    else:  # HOD, ADMIN
        if current_project:
            tasks = Task.objects.filter(project=current_project)
        else:
            tasks = Task.objects.filter(project__in=projects)

    # -----------------------------
    # FILTERS
    # -----------------------------
    q = request.GET.get('q')
    status = request.GET.get('status')
    priority = request.GET.get('priority')
    team_filter = request.GET.get('team')

    if q:
        tasks = tasks.filter(title__icontains=q)
    if status:
        tasks = tasks.filter(status=status)
    if priority:
        tasks = tasks.filter(priority=priority)
    if team_filter:
        tasks = tasks.filter(team__id=team_filter)

    # -----------------------------
    # CONTEXT
    # -----------------------------
    context = {
        'projects': projects,
        'tasks': tasks,
        'teams': teams,
        'current_project': current_project,
        'active_tab': 'backlog',
        'staff_and_students': staff_and_students,
    }

    return render(request, 'accounts/backlog.html', context)



# New view for students to see their tasks
def student_dashboard(request):
    user = request.user
    tasks = Task.objects.filter(assigned_to=user)

    # Kanban tasks
    kanban_tasks = {
        'to_do': tasks.filter(status='to_do'),
        'in_progress': tasks.filter(status='in_progress'),
        'in_review': tasks.filter(status='in_review'),
        'done': tasks.filter(status='done'),
    }

    # Counts
    completed_count = tasks.filter(status='done', updated_at__gte=date.today()-timedelta(days=7)).count()
    updated_count = tasks.filter(updated_at__gte=date.today()-timedelta(days=7)).count()
    in_progress_count = kanban_tasks['in_progress'].count()
    todo_count = kanban_tasks['to_do'].count()
    done_count = kanban_tasks['done'].count()
    created_count = tasks.filter(created_at__gte=date.today()-timedelta(days=7)).count()

    # due soon (next 7 days)
    due_soon_count = tasks.filter(due_date__range=[date.today(), date.today() + timedelta(days=7)]).count()

    context = {
        'kanban_tasks': kanban_tasks,
        'completed_count': completed_count,
        'updated_count': updated_count,
        'in_progress_count': in_progress_count,
        'todo_count': todo_count,
        'done_count': done_count,
        'created_count': created_count,
        'due_soon_count': due_soon_count,
        'active_tab': 'summary',
    }

    return render(request, 'accounts/student_dashboard.html', context)

@login_required
def teams_page(request):

    # --------------------------------------------------------
    # ROLE-BASED PROJECT FILTERING (M2M)
    # --------------------------------------------------------
    if request.user.role == 'coordinator':
        projects = Project.objects.filter(
            department__campus=request.user.campus
        ).distinct()

        users = CustomUser.objects.filter(
            campus=request.user.campus,
            role__in=['staff', 'student']
        ).distinct().order_by('email')

    elif request.user.role == 'hod':
        projects = Project.objects.filter(
            department__school=request.user.school
        ).distinct()

        users = CustomUser.objects.filter(
            school=request.user.school,
            role__in=['staff', 'student']
        ).distinct().order_by('email')

    else:  # staff
        projects = Project.objects.filter(
            department__in=request.user.department.all()
        ).distinct()

        users = CustomUser.objects.filter(
            department__in=request.user.department.all(),
            role__in=['staff', 'student']
        ).distinct().order_by('email')



    # --------------------------------------------------------
    # TEAMS CONNECTED TO THESE PROJECTS
    # --------------------------------------------------------
    teams = Team.objects.filter(
        project__in=projects
    ).select_related('project', 'head').prefetch_related('members')


    # --------------------------------------------------------
    # TEAM STATISTICS
    # --------------------------------------------------------
    teams_with_projects = teams.filter(project__isnull=False).count()
    total_team_heads = teams.values('head').distinct().count()

    # Unique members
    all_member_ids = set()
    for team in teams:
        if team.head:
            all_member_ids.add(team.head.id)
        all_member_ids.update(team.members.values_list('id', flat=True))

    total_members = len(all_member_ids)


    context = {
        'teams': teams,
        'projects': projects,
        'staff_and_students': users,  # UPDATED
        'teams_with_projects': teams_with_projects,
        'total_team_heads': total_team_heads,
        'total_members': total_members,
    }

    return render(request, 'accounts/teams_page.html', context)



@login_required
def projects_page(request):

    # --------------------------------------------------------
    # ROLE-BASED PROJECT FILTERING (M2M via Department)
    # --------------------------------------------------------
    if request.user.role == 'coordinator':
        projects = Project.objects.filter(
            department__campus=request.user.campus
        ).distinct().prefetch_related('teams', 'tasks')

        users = CustomUser.objects.filter(
            campus=request.user.campus,
            role__in=['staff', 'student']
        ).distinct().order_by('email')

    elif request.user.role == 'hod':
        projects = Project.objects.filter(
            department__school=request.user.school
        ).distinct().prefetch_related('teams', 'tasks')

        users = CustomUser.objects.filter(
            school=request.user.school,
            role__in=['staff', 'student']
        ).distinct().order_by('email')

    else:  # staff
        projects = Project.objects.filter(
            department__in=request.user.department.all()
        ).distinct().prefetch_related('teams', 'tasks')

        users = CustomUser.objects.filter(
            department__in=request.user.department.all(),
            role__in=['staff', 'student']
        ).distinct().order_by('email')



    # --------------------------------------------------------
    # TEAMS BASED ON FILTERED PROJECTS
    # --------------------------------------------------------
    project_ids = projects.values_list('id', flat=True)

    teams = Team.objects.filter(
        project_id__in=project_ids
    ).select_related('project', 'head').prefetch_related('members')


    # --------------------------------------------------------
    # PROJECT STATUS COUNTERS
    # --------------------------------------------------------
    ongoing = completed = upcoming = 0

    for project in projects:
        if project.status == "ongoing":
            ongoing += 1
        elif project.status == "completed":
            completed += 1
        elif project.status == "upcoming":
            upcoming += 1


    context = {
        'projects': projects,
        'teams': teams,
        'staff_and_students': users,  # UPDATED
        'ongoing_projects': ongoing,
        'completed_projects': completed,
        'upcoming_projects': upcoming,
    }

    return render(request, 'accounts/projects_page.html', context)


    
@login_required
def create_team(request):
    """Create a new team with role-based access and project/user filtering."""

    # ---------------------------------------------------
    # 1. FETCH PROJECTS BASED ON USER ROLE
    # ---------------------------------------------------
    if request.user.role == 'coordinator':
        allowed_projects = Project.objects.filter(
            department__campus=request.user.campus
        ).distinct()

        allowed_users = CustomUser.objects.filter(
            campus=request.user.campus,
            role__in=['staff', 'student']
        ).distinct()

    elif request.user.role == 'hod':
        allowed_projects = Project.objects.filter(
            department__school=request.user.school
        ).distinct()

        allowed_users = CustomUser.objects.filter(
            school=request.user.school,
            role__in=['staff', 'student']
        ).distinct()

    else:  # staff
        allowed_projects = Project.objects.filter(
            department=request.user.department
        ).distinct()

        allowed_users = CustomUser.objects.filter(
            department=request.user.department,
            role__in=['staff', 'student']
        ).distinct()

    # ---------------------------------------------------
    # 2. PROCESS FORM SUBMISSION
    # ---------------------------------------------------
    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        project_id = request.POST.get("project")
        head_id = request.POST.get("head")
        member_ids = request.POST.getlist("members")

        # REQUIRED FIELDS VALIDATION
        if not name:
            messages.error(request, "Team name is required.")
            return redirect(request.META.get("HTTP_REFERER", "accounts:teams"))

        if not project_id:
            messages.error(request, "Project is required.")
            return redirect(request.META.get("HTTP_REFERER", "accounts:teams"))

        if not head_id:
            messages.error(request, "Team lead is required.")
            return redirect(request.META.get("HTTP_REFERER", "accounts:teams"))

        try:
            # ---------------------------------------------------
            # 3. VALIDATE PROJECT ACCESS
            # ---------------------------------------------------
            if not allowed_projects.filter(id=project_id).exists():
                messages.error(request, "You are not allowed to create teams for this project.")
                return redirect(request.META.get("HTTP_REFERER", "accounts:teams"))

            project = Project.objects.get(id=project_id)

            # ---------------------------------------------------
            # 4. VALIDATE HEAD ACCESS
            # ---------------------------------------------------
            if not allowed_users.filter(id=head_id).exists():
                messages.error(request, "You cannot select this user as a team lead.")
                return redirect(request.META.get("HTTP_REFERER", "accounts:teams"))

            head = CustomUser.objects.get(id=head_id)

            # ---------------------------------------------------
            # 5. VALIDATE MEMBER ACCESS
            # ---------------------------------------------------
            for mid in member_ids:
                if not allowed_users.filter(id=mid).exists():
                    messages.error(request, "One or more selected members are not allowed.")
                    return redirect(request.META.get("HTTP_REFERER", "accounts:teams"))

            # ---------------------------------------------------
            # 6. PREFIX NAME USING PROJECT KEYWORD
            # ---------------------------------------------------
            keyword = (project.keyword or "").strip()
            final_name = f"{keyword} - {name}" if keyword else name

            # CREATE TEAM
            team = Team.objects.create(
                name=final_name,
                project=project,
                staff=request.user,
                head=head
            )

            # ALWAYS INCLUDE HEAD AS MEMBER
            final_member_ids = set(member_ids)
            final_member_ids.add(str(head_id))

            members = CustomUser.objects.filter(id__in=final_member_ids)
            team.members.set(members)

            messages.success(
                request,
                f"Team '{final_name}' created successfully! Team lead '{head.username}' added as member."
            )
            return redirect(request.META.get("HTTP_REFERER", "accounts:teams"))

        except Project.DoesNotExist:
            messages.error(request, "Selected project does not exist.")
        except CustomUser.DoesNotExist:
            messages.error(request, "Selected head/member does not exist.")
        except Exception as e:
            messages.error(request, f"Error creating team: {str(e)}")

        return redirect(request.META.get("HTTP_REFERER", "accounts:teams"))

    # ---------------------------------------------------
    # 7. DEFAULT REDIRECT
    # ---------------------------------------------------
    return redirect("accounts:teams")



@login_required
def edit_team(request, team_id):
    """Edit an existing team while keeping team head inside members list"""
    
    team = get_object_or_404(Team, id=team_id)

    if request.method == 'POST':
        new_name = request.POST.get('name', '').strip()
        new_head_id = request.POST.get('head')
        new_member_ids = request.POST.getlist('members')
        new_project_id = request.POST.get('project')

        # VALIDATION
        if not new_name:
            messages.error(request, "Team name cannot be empty.")
            return redirect(request.META.get("HTTP_REFERER", "accounts:teams_page"))

        if not new_head_id:
            messages.error(request, "Team lead is required.")
            return redirect(request.META.get("HTTP_REFERER", "accounts:teams_page"))

        try:
            # PROJECT UPDATED?
            if new_project_id:
                project = get_object_or_404(Project, id=new_project_id)
                team.project = project
                keyword = (project.keyword or "").strip()
            else:
                keyword = (team.project.keyword or "").strip()

            # ✅ APPLY PREFIX EVERY TIME
            final_name = f"{keyword} - {new_name}" if keyword else new_name
            team.name = final_name

            # UPDATE HEAD
            new_head = get_object_or_404(CustomUser, id=new_head_id)
            team.head = new_head

            team.save()

            # MEMBERS INCLUDING HEAD
            final_member_ids = set(new_member_ids)
            final_member_ids.add(str(new_head_id))

            members = CustomUser.objects.filter(id__in=final_member_ids)
            team.members.set(members)

            messages.success(request, f"Team '{final_name}' updated successfully!")
            return redirect(request.META.get("HTTP_REFERER", "accounts:teams_page"))

        except CustomUser.DoesNotExist:
            messages.error(request, "Selected user does not exist.")
            return redirect(request.META.get("HTTP_REFERER", "accounts:teams_page"))

        except Project.DoesNotExist:
            messages.error(request, "Selected project does not exist.")
            return redirect(request.META.get("HTTP_REFERER", "accounts:teams_page"))

        except Exception as e:
            messages.error(request, f"Error updating team: {str(e)}")
            return redirect(request.META.get("HTTP_REFERER", "accounts:teams_page"))

    return redirect("accounts:teams_page")



@login_required
def delete_team(request, team_id):
    """Delete a team"""
    team = get_object_or_404(Team, id=team_id)
    team_name = team.name
    
    try:
        team.delete()
        messages.success(request, f"Team '{team_name}' deleted successfully!")
    except Exception as e:
        messages.error(request, f"Error deleting team: {str(e)}")
    
    return redirect(request.META.get("HTTP_REFERER", "accounts:teams"))


@login_required
def get_users_in_team(request, team_id):
    """Return JSON of users in a team (for AJAX calls)."""
    team = get_object_or_404(Team, id=team_id)
    users = [{'id': user.id, 'username': user.username, 'email': user.email} for user in team.members.all()]
    return JsonResponse({'users': users})


# View to assign work to students
@login_required
def assign_work(request):
    if request.user.role != 'staff':
        messages.error(request, "You do not have permission to assign work.")
        return redirect('accounts:staff_dashboard')

    if request.method == 'POST':
        team_id = request.POST.get('team_id')
        student_ids = request.POST.getlist('student_ids')
        task_desc = request.POST.get('task_description')

        if team_id and student_ids and task_desc:
            from .models import Team, Task
            team = Team.objects.get(id=team_id)
            for sid in student_ids:
                student = CustomUser.objects.get(id=sid)
                Task.objects.create(team=team, student=student, description=task_desc)
            messages.success(request, "Work assigned successfully!")
        else:
            messages.error(request, "All fields are required.")

    return redirect('accounts:staff_dashboard')


def add_staff(request):
    if request.method == 'POST':
        form = AddStaffForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Staff member added successfully!')
            return redirect('accounts:hod_dashboard')
        else:
            messages.error(request, 'There were errors in the form. Please fix them below.')
            print(form.errors)  # helpful for debugging
    else:
        form = AddStaffForm()

    return render(request, 'accounts/add_staff.html', {'form': form})

@login_required
def add_hod(request):
    # Ensure only admin can add HODs
    if request.user.role != 'admin':
        messages.error(request, "You do not have permission to add HOD.")
        return redirect('accounts:admin_dashboard')

    if request.method == 'POST':
        form = HODRegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.role = 'hod'  # Set the role to HOD
            user.save()

            # Automatically create a social account for this HOD's email
            email = user.email
            # Check if the email is already linked with a social account
            social_account = SocialAccount.objects.filter(user=user).first()
            if not social_account:
                # Create a new social account for the user
                social_account = SocialAccount(user=user, provider='email')
                social_account.save()
            
            # Make sure the email address is confirmed for this user
            email_address = EmailAddress.objects.get_or_create(user=user, email=email, verified=True)
            
            # Optionally, you can create an EmailAddress instance for the social account if necessary.
            # Redirect to the admin dashboard after success
            messages.success(request, f'HOD {user.username} added successfully!')
            return redirect('accounts:admin_dashboard')

    else:
        form = HODRegisterForm()

    return render(request, 'accounts/add_hod.html', {'form': form})


@login_required
def user_detail(request, user_id):
    # Get the user by their ID
    user = get_object_or_404(CustomUser, id=user_id)
    return render(request, 'accounts/user_detail.html', {'user': user})


@login_required
def edit_user(request, user_id):
    # Fetch the user by ID
    user = get_object_or_404(CustomUser, id=user_id)

    # Ensure only admin or HOD can edit staff
    if request.user.role not in ['admin', 'hod']:
        messages.error(request, "You do not have permission to edit this user.")
        return redirect('accounts:dashboard')  # Redirect to a safe page

    # Handle form submission
    if request.method == 'POST':
        form = HODRegisterForm(request.POST, instance=user)  # Or a custom StaffEditForm
        if form.is_valid():
            form.save()
            messages.success(request, "User details updated successfully!")
            # Redirect to HOD staff management page
            return redirect('accounts:hod_staff')
        else:
            messages.error(request, "There were errors in the form. Please try again.")
    else:
        form = HODRegisterForm(instance=user)

    return render(request, 'accounts/edit_user.html', {'form': form, 'user': user})



# Remove User View
@login_required
def remove_user(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)

    # Make sure only admin can delete users
    if request.user.role != 'admin':
        messages.error(request, "You do not have permission to remove this user.")
        return redirect('accounts:admin_dashboard')

    if request.method == 'POST':
        user.delete()
        messages.success(request, "User removed successfully!")
        return redirect('accounts:admin_dashboard')

    return render(request, 'accounts/confirm_remove_user.html', {'user': user})

# View for unregistered users
def email_not_registered(request):
    return render(request, 'accounts/email_not_registered.html')



@require_POST
def start_task_timer(request):
    task_id = request.POST.get('task_id')
    try:
        task = Task.objects.get(id=task_id)

        # Start only if task is not already in progress
        if task.status != 'in_progress':

            # DO NOT RESET accumulated_time (your bug)
            # Only set new timer start point
            task.status = 'in_progress'
            task.start_time = timezone.now()
            task.is_paused = False
            task.pause_time = None
            task.save()

            return JsonResponse({'success': True})

        return JsonResponse({'success': False, 'error': 'Task already in progress'})

    except Task.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Task not found'})

@require_POST
def pause_task_timer(request):
    task_id = request.POST.get('task_id')
    accumulated_time = int(request.POST.get('accumulated_time', 0))

    try:
        task = Task.objects.get(id=task_id)

        if task.status == 'in_progress' and not task.is_paused:

            # Save accumulated seconds
            task.accumulated_time = accumulated_time

            # Pause the timer
            task.is_paused = True
            task.pause_time = timezone.now()
            task.start_time = None

            task.save()

            return JsonResponse({'success': True})

        return JsonResponse({'success': False, 'error': 'Task not in progress or already paused'})

    except Task.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Task not found'})

@require_POST
def resume_task_timer(request):
    task_id = request.POST.get('task_id')

    try:
        task = Task.objects.get(id=task_id)

        if task.status == 'in_progress' and task.is_paused:

            task.is_paused = False
            task.start_time = timezone.now()  # Resume tracking
            task.pause_time = None

            task.save()

            return JsonResponse({
                'success': True,
                'start_time': task.start_time.isoformat()
            })

        return JsonResponse({'success': False, 'error': 'Task not paused'})

    except Task.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Task not found'})

@require_POST
def update_task_status(request):
    task_id = request.POST.get('task_id')
    new_status = request.POST.get('new_status')
    total_time = request.POST.get('total_time')

    try:
        task = Task.objects.get(id=task_id)
        old_status = task.status

        # -----------------------------------------
        # 1️⃣ Capture time if task was in_progress
        # -----------------------------------------
        if old_status == 'in_progress' and task.start_time:
            elapsed = int((timezone.now() - task.start_time).total_seconds())
            task.accumulated_time += elapsed
            task.start_time = None
            task.is_paused = True

        # -----------------------------------------
        # 2️⃣ Move to DONE → finalize time
        # -----------------------------------------
        if new_status == 'done':
            if task.accumulated_time:
                task.total_time_seconds = task.accumulated_time
                task.total_time = timedelta(seconds=task.accumulated_time)

            task.end_time = timezone.now()
            task.is_paused = True
            task.start_time = None

        # -----------------------------------------
        # 3️⃣ Move to in_progress → resume timer
        # -----------------------------------------
        elif new_status == 'in_progress':
            task.start_time = timezone.now()
            task.is_paused = False
            task.end_time = None

        # -----------------------------------------
        # 4️⃣ Move to to_do → DO NOT reset accumulated_time
        # -----------------------------------------
        elif new_status == 'to_do':
            task.start_time = None
            task.is_paused = True
            # accumulated_time stays intact

        # Update status
        task.status = new_status
        task.save()

        # Return back to the same page
        return redirect(request.META.get('HTTP_REFERER', '/'))

    except Task.DoesNotExist:
        messages.error(request, "Task not found")
        return redirect(request.META.get('HTTP_REFERER', '/'))


@csrf_exempt
@require_POST
def update_subtask_time(request):
    subtask_id = request.POST.get('subtask_id')
    time_spent = int(request.POST.get('time_spent', 0))
    
    try:
        subtask = SubTask.objects.get(id=subtask_id)
        
        # Update time_spent_seconds field
        subtask.time_spent_seconds = time_spent
        
        # Update total_time as timedelta if field exists
        from datetime import timedelta
        if hasattr(subtask, 'total_time'):
            subtask.total_time = timedelta(seconds=time_spent)
        
        subtask.save()
        return JsonResponse({
            'success': True,
            'time_spent_seconds': subtask.time_spent_seconds
        })
    except SubTask.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Subtask not found'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})



@login_required
def create_event(request):
    if request.user.role not in ['staff', 'hod', 'admin']:
        messages.error(request, "You do not have permission to create events.")
        return redirect('accounts:dashboard')

    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        start_date = request.POST.get('start_date')
        end_date = request.POST.get('end_date')

        if title and start_date and end_date:
            Event.objects.create(
                title=title,
                description=description,
                start_date=start_date,
                end_date=end_date,
                created_by=request.user
            )
            messages.success(request, "Event created successfully!")
            return redirect('accounts:dashboard')
        else:
            messages.error(request, "Please fill all required fields.")

    return render(request, 'accounts/create_event.html')


def all_projects(request):
    return {
        'projects': Project.objects.all()
    }

from .forms import CampusForm
from .models import Campus, School, Department 
def create_campus(request):
    if request.method == "POST":
        form = CampusForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('accounts:campus_crud')
    else:
        form = CampusForm()
    
    campuses = Campus.objects.all()
    return render(request, 'accounts/campus_crud.html', {'form': form, 'campuses': campuses})


# Campus CRUD
def campus_crud(request):
    # Add campus
    if request.method == "POST":
        name = request.POST.get("name")
        if name:
            Campus.objects.create(name=name)
            return redirect('accounts:campus_crud')

    # GET request: show all campuses
    campuses = Campus.objects.all()
    return render(request, 'accounts/campus_crud.html', {'campuses': campuses})


# Delete campus
def delete_campus(request, campus_id):
    campus = get_object_or_404(Campus, id=campus_id)
    campus.delete()
    return redirect('accounts:campus_crud')


# Edit campus
def edit_campus(request, campus_id):
    campus = get_object_or_404(Campus, id=campus_id)

    if request.method == "POST":
        name = request.POST.get("name")
        if name:
            campus.name = name
            campus.save()
            return redirect('accounts:campus_crud')

    return render(request, 'accounts/edit_campus.html', {'campus': campus})

# School CRUD
def school_crud(request):
    if request.method == "POST":
        name = request.POST.get("name")
        campus_id = request.POST.get("campus")
        if name and campus_id:
            campus = get_object_or_404(Campus, id=campus_id)
            School.objects.create(name=name, campus=campus)
            return redirect('accounts:school_crud')

    schools = School.objects.select_related('campus').all()
    campuses = Campus.objects.all()
    return render(request, 'accounts/school_crud.html', {'schools': schools, 'campuses': campuses})


# Delete school
def delete_school(request, school_id):
    school = get_object_or_404(School, id=school_id)
    school.delete()
    return redirect('accounts:school_crud')


# Edit school
def edit_school(request, school_id):
    school = get_object_or_404(School, id=school_id)
    campuses = Campus.objects.all()

    if request.method == "POST":
        name = request.POST.get("name")
        campus_id = request.POST.get("campus")
        if name and campus_id:
            campus = get_object_or_404(Campus, id=campus_id)
            school.name = name
            school.campus = campus
            school.save()
            return redirect('accounts:school_crud')

    return render(request, 'accounts/edit_school.html', {'school': school, 'campuses': campuses})



def department_crud(request):
    campuses = Campus.objects.all()
    schools = School.objects.all()
    departments = Department.objects.all()

    # ADD Department
    if request.method == "POST" and 'add_department' in request.POST:
        campus_id = request.POST.get("campus")
        school_id = request.POST.get("school")
        department_name = request.POST.get("name")

        if campus_id and school_id and department_name:
            campus = Campus.objects.get(id=campus_id)
            school = School.objects.get(id=school_id)
            Department.objects.create(
                name=department_name,
                campus=campus,
                school=school
            )
        return redirect('accounts:department_crud')

    # EDIT Department
    if request.method == "POST" and 'edit_department' in request.POST:
        dept_id = request.POST.get("dept_id")
        department = get_object_or_404(Department, id=dept_id)
        department.name = request.POST.get("name")
        department.campus = Campus.objects.get(id=request.POST.get("campus"))
        department.school = School.objects.get(id=request.POST.get("school"))
        department.save()
        return redirect('accounts:department_crud')

    # DELETE Department
    if request.method == "POST" and 'delete_department' in request.POST:
        dept_id = request.POST.get("dept_id")
        department = get_object_or_404(Department, id=dept_id)
        department.delete()
        return redirect('accounts:department_crud')

    context = {
        'campuses': campuses,
        'schools': schools,
        'departments': departments
    }
    return render(request, 'accounts/department_crud.html', context)

def edit_department(request, id):
    department = Department.objects.get(id=id)
    campuses = Campus.objects.all()
    schools = School.objects.all()

    if request.method == 'POST':
        department.name = request.POST.get('name')
        department.campus = Campus.objects.get(id=request.POST.get('campus'))
        department.school = School.objects.get(id=request.POST.get('school'))
        department.save()
        return redirect('accounts:department_crud')  

    context = {
        'department': department,
        'campuses': campuses,
        'schools': schools
    }
    return render(request, 'accounts/edit_department.html', context)


def delete_department(request, id):
    department = get_object_or_404(Department, id=id)  # safer
    department.delete()
    return redirect('accounts:department_crud')


def create_user(request):
    # Fetch data for dropdowns and table
    campuses = Campus.objects.all()
    schools = School.objects.all()
    departments = Department.objects.all()
    users = CustomUser.objects.all().order_by('-id')  # newest first

    if request.method == 'POST':
        # Fetch form data
        username = request.POST.get('username')
        email = request.POST.get('email')
        emp_id = request.POST.get('emp_id')
        phone_number = request.POST.get("phone_number")
        gender = request.POST.get('gender')
        campus_id = request.POST.get('campus')
        school_id = request.POST.get('school')
        department_ids = request.POST.getlist('department')  # 🔹 multiple selection
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        # Validation
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect('accounts:create_user')

        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return redirect('accounts:create_user')

        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
            return redirect('accounts:create_user')

        # Fetch related objects safely
        campus = Campus.objects.get(id=campus_id) if campus_id else None
        school = School.objects.get(id=school_id) if school_id else None

        # Create user
        user = CustomUser(
            username=username,
            email=email,
            emp_id=emp_id,
            phone_number=phone_number,
            gender=gender,
            campus=campus,
            school=school
        )
        user.set_password(password)
        user.save()

        # 🔹 Assign departments (ManyToMany)
        if department_ids:
            user.department.set(Department.objects.filter(id__in=department_ids))

        messages.success(request, f"User '{username}' created successfully.")
        return redirect('accounts:create_user')

    context = {
        'campuses': campuses,
        'schools': schools,
        'departments': departments,
        'users': users
    }
    return render(request, 'accounts/create_user.html', context)


def manage_user(request):
    users = CustomUser.objects.all()
    campuses = Campus.objects.all()
    schools = School.objects.all()
    departments = Department.objects.all()
    return render(request, 'accounts/manage_user.html', {
        'users': users,
        'campuses': campuses,
        'schools': schools,
        'departments': departments,
    })

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect
from .models import CustomUser, Campus, School, Department

@login_required
def update_user_role(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)

    # Only admins can update roles
    if not hasattr(request.user, "role") or request.user.role != "admin":
        return HttpResponseForbidden("You are not authorized to perform this action.")

    if request.method == "POST":
        # Get values from form
        email = request.POST.get("email")
        emp_id = request.POST.get("emp_id")
        phone_number = request.POST.get("phone_number")
        gender = request.POST.get("gender")
        role = request.POST.get("role")

        campus_id = request.POST.get("campus") or None
        school_id = request.POST.get("school") or None
        dept_ids = request.POST.getlist("department")  # multiple departments

        # Validate phone number
        if phone_number and not phone_number.isdigit():
            messages.error(request, f"Phone number must contain only digits for {user.email}.")
            return redirect("/accounts/create_user/")

        # Check for duplicates
        if email and CustomUser.objects.exclude(id=user.id).filter(email=email).exists():
            messages.error(request, f"Email '{email}' is already taken.")
            return redirect("/accounts/create_user/")

        if emp_id and CustomUser.objects.exclude(id=user.id).filter(emp_id=emp_id).exists():
            messages.error(request, f"Employee ID '{emp_id}' is already taken.")
            return redirect("/accounts/create_user/")

        if phone_number and CustomUser.objects.exclude(id=user.id).filter(phone_number=phone_number).exists():
            messages.error(request, f"Phone number '{phone_number}' is already taken.")
            return redirect("/accounts/create_user/")

        # Validate school belongs to campus
        if school_id and not School.objects.filter(id=school_id, campus_id=campus_id).exists():
            messages.error(request, "Invalid selection: School does not belong to the chosen Campus.")
            return redirect("/accounts/create_user/")

        # Validate departments belong to school
        if dept_ids:
            valid_dept_ids = Department.objects.filter(id__in=dept_ids, school_id=school_id).values_list('id', flat=True)
            if set(map(int, dept_ids)) != set(valid_dept_ids):
                messages.error(request, "Invalid selection: One or more Departments do not belong to the chosen School.")
                return redirect("/accounts/create_user/")

        # Update user
        if email:
            user.email = email
        if emp_id:
            user.emp_id = emp_id
        if phone_number:
            user.phone_number = phone_number
        if gender:
            user.gender = gender
        if role:
            user.role = role

        user.campus_id = campus_id
        user.school_id = school_id
        user.save()

        # Update ManyToMany Departments
        if dept_ids:
            user.department.set(dept_ids)
        else:
            user.department.clear()

        messages.success(request, f"User {user.username} updated successfully.")

    # Redirect to create_user page
    return redirect("/accounts/create_user/")




@login_required
def update_user_role_only(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)

    # Only admins can update roles
    if not hasattr(request.user, "role") or request.user.role != "admin":
        return HttpResponseForbidden("You are not authorized to perform this action.")

    if request.method == "POST":
        role = request.POST.get("role")

        allowed_roles = ["admin", "hod", "coordinator", "staff", "student"]

        if role not in allowed_roles:
            messages.error(request, "Invalid role selected.")
            return redirect("accounts:manage_roles")

        # Update role
        user.role = role
        user.save()

        # EXTRA LOGIC FOR COORDINATOR
        if role == "coordinator":
            if user.campus:
                # Assign all schools of coordinator's campus
                schools = School.objects.filter(campus=user.campus)
                if schools.exists():
                    # Assign first school as primary (optional)
                    user.school = schools.first()
                    user.save()

                    # Assign ALL departments under those schools
                    departments = Department.objects.filter(school__in=schools)
                    user.department.set(departments)
                else:
                    messages.warning(request, "No schools found for this coordinator's campus.")
            else:
                messages.warning(request, "Coordinator must have a campus assigned!")

        messages.success(request, f"Role of {user.username} updated to {role}.")

    return redirect("accounts:manage_roles")


@login_required
def manage_roles(request):
    if not hasattr(request.user, "role") or request.user.role != "admin":
        return HttpResponseForbidden("You are not authorized to access this page.")

    users = CustomUser.objects.all().order_by('id')

    return render(request, 'accounts/manage_roles.html', {
        'users': users,
    })

def get_current_project(request, projects):
    project_id = request.GET.get('project')
    if project_id:
        return get_object_or_404(projects, id=project_id)
    return projects.first() if projects.exists() else None
    
@login_required
def delete_user(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    user.delete()
    return redirect('accounts:create_user')

def create_campus(request):
    if request.method == "POST":
        form = CampusForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('accounts:campus_crud')  # redirect after creation
    else:
        form = CampusForm()
    
    context = {'form': form}
    return render(request, 'accounts/create_campus.html', context)



from django.views.decorators.csrf import csrf_exempt
@csrf_exempt
def create_school(request):
    if request.method == "POST":
        name = request.POST.get("name")
        campus_id = request.POST.get("campus")
        if name and campus_id:
            campus = Campus.objects.get(id=campus_id)
            School.objects.create(name=name, campus=campus)
        return redirect('accounts:admin_dashboard')

@csrf_exempt
def create_department(request):
    if request.method == "POST":
        name = request.POST.get("name")
        campus_id = request.POST.get("campus")
        school_id = request.POST.get("school")
        if name and campus_id and school_id:
            campus = Campus.objects.get(id=campus_id)
            school = School.objects.get(id=school_id)
            Department.objects.create(name=name, campus=campus, school=school)
        return redirect('accounts:admin_dashboard')

# Your views already have staff_and_students! ✅
# Just make sure coordinator_dashboard also has it:

@login_required
def coordinator_dashboard(request):
    user = request.user

    if user.role != "coordinator":
        return redirect("accounts:login")

    now = timezone.now()
    today = now.date()

    # Helper: Pure date-based status logic
    def get_project_status(project):
        if project.start_date and project.end_date:
            if today < project.start_date:
                return "upcoming"
            elif project.start_date <= today <= project.end_date:
                return "ongoing"
            elif today > project.end_date:
                return "completed"
        return "upcoming"

    # ---------------------------------------------------
    # 1️⃣ Extract Campus → Schools → Departments
    # ---------------------------------------------------
    coordinator_campus = user.campus

    schools = School.objects.filter(campus=coordinator_campus)
    departments = Department.objects.filter(school__in=schools)
    campus_users = CustomUser.objects.filter(campus=coordinator_campus)

    # ---------------------------------------------------
    # 2️⃣ School Filter
    # ---------------------------------------------------
    selected_school_id = request.GET.get('school')
    selected_school = None

    if selected_school_id:
        selected_school = School.objects.filter(
            id=selected_school_id,
            campus=coordinator_campus
        ).first()

        if selected_school:
            departments = departments.filter(school=selected_school)
            campus_users = campus_users.filter(school=selected_school)

    # ---------------------------------------------------
    # 3️⃣ Project Query
    # ---------------------------------------------------
    projects_qs = Project.objects.filter(
        Q(created_by__in=campus_users) |
        Q(tasks__assigned_to__in=campus_users) |
        Q(teams__members__in=campus_users) |
        Q(department__in=departments)
    ).distinct()

    # ---------------------------------------------------
    # 4️⃣ Persist Selected Project
    # ---------------------------------------------------
    if request.GET.get("project") is not None:
        request.session["selected_project_id"] = request.GET.get("project")

    selected_project_id = request.GET.get("project") or request.session.get("selected_project_id")
    current_project = projects_qs.filter(id=selected_project_id).first() if selected_project_id else None

    # ---------------------------------------------------
    # 5️⃣ Tasks
    # ---------------------------------------------------
    tasks_qs = Task.objects.filter(
        Q(project__in=projects_qs) |
        Q(assigned_to__in=campus_users) |
        Q(team__members__in=campus_users)
    ).distinct()

    if current_project:
        tasks_qs = tasks_qs.filter(project=current_project)

    kanban_tasks = {
        "to_do": list(tasks_qs.filter(status="to_do")),
        "in_progress": list(tasks_qs.filter(status="in_progress")),
        "in_review": list(tasks_qs.filter(status="in_review")),
        "done": list(tasks_qs.filter(status="done")),
    }

    todo_count = len(kanban_tasks["to_do"])
    in_progress_count = len(kanban_tasks["in_progress"])
    in_review_count = len(kanban_tasks["in_review"])
    done_count = len(kanban_tasks["done"])

    completed_count = tasks_qs.filter(status="done", updated_at__gte=now - timedelta(days=7)).count()
    updated_count = tasks_qs.filter(updated_at__gte=now - timedelta(days=7)).count()
    created_count = tasks_qs.filter(created_at__gte=now - timedelta(days=7)).count()
    due_soon_count = tasks_qs.filter(
        due_date__lte=now + timedelta(days=7),
        due_date__gte=now,
        status__in=["to_do", "in_progress"]
    ).count()

    # ---------------------------------------------------
    # 6️⃣ Teams
    # ---------------------------------------------------
    all_allowed_teams = Team.objects.filter(
        Q(project__in=projects_qs) |
        Q(members__in=campus_users)
    ).distinct()

    teams = all_allowed_teams.filter(project=current_project) if current_project else all_allowed_teams

    # ---------------------------------------------------
    # 🆕 ADD THIS: Staff and Students for Filters
    # ---------------------------------------------------
    staff_and_students = CustomUser.objects.filter(
        campus=coordinator_campus,
        role__in=['staff', 'student']
    ).order_by('email').distinct()

    # ---------------------------------------------------
    # 7️⃣ 🔥 Project Status Analytics (Using DATE ONLY)
    # ---------------------------------------------------
    total_projects = projects_qs.count()
    ongoing_projects = 0
    upcoming_projects = 0
    completed_projects = 0

    for project in projects_qs:
        status = get_project_status(project)
        if status == "ongoing":
            ongoing_projects += 1
        elif status == "upcoming":
            upcoming_projects += 1
        elif status == "completed":
            completed_projects += 1

    # ---------------------------------------------------
    # 8️⃣ Schools with Project Counts
    # ---------------------------------------------------
    schools_with_counts = []
    for school in schools:
        school_departments = Department.objects.filter(school=school)
        count = projects_qs.filter(department__in=school_departments).distinct().count()

        schools_with_counts.append({
            "id": school.id,
            "name": school.name,
            "project_count": count
        })

    # ---------------------------------------------------
    # 9️⃣ Departments with Project Counts
    # ---------------------------------------------------
    departments_with_counts = []
    for dept in departments:
        count = projects_qs.filter(department=dept).count()
        departments_with_counts.append({
            "id": dept.id,
            "name": dept.name,
            "school_name": dept.school.name,
            "project_count": count
        })

    # ---------------------------------------------------
    # 🔟 Recent Projects List (DATE BASED STATUS)
    # ---------------------------------------------------
    recent_projects_list = []
    for project in projects_qs.order_by('-created_at')[:20]:
        school_name = project.department.first().school.name if project.department.exists() else "No School"
        recent_projects_list.append({
            'id': project.id,
            'name': project.name,
            'school': school_name,
            'start_date': project.start_date,
            'end_date': project.end_date,
            'status': get_project_status(project)
        })

    context = {
        "active_tab": "summary",
        "kanban_tasks": kanban_tasks,
        "todo_count": todo_count,
        "in_progress_count": in_progress_count,
        "in_review_count": in_review_count,
        "done_count": done_count,
        "completed_count": completed_count,
        "updated_count": updated_count,
        "created_count": created_count,
        "due_soon_count": due_soon_count,

        "projects": projects_qs,
        "schools": schools_with_counts,
        "departments": departments_with_counts,
        "teams": teams,
        "current_project": current_project,
        "selected_school": selected_school,

        "total_projects": total_projects,
        "ongoing_projects": ongoing_projects,
        "upcoming_projects": upcoming_projects,
        "completed_projects": completed_projects,

        "total_departments": departments.count(),
        "total_schools": schools.count(),
        "total_teams": teams.count(),
        "recent_projects": recent_projects_list,

        # 🆕 ADD THIS LINE
        "staff_and_students": staff_and_students,

        "is_read_only": True,
    }

    return render(request, "accounts/summary.html", context)

@login_required
def coordinator_dashboard_1(request):
    user = request.user

    if user.role != "coordinator":
        return redirect("accounts:login")

    now = timezone.now()
    today = now.date()

    # Helper: Date-based status
    def get_project_status(project):
        if project.start_date and project.end_date:
            if today < project.start_date:
                return "upcoming"
            elif project.start_date <= today <= project.end_date:
                return "ongoing"
            elif today > project.end_date:
                return "completed"
        return "upcoming"

    # ---------------------------------------------------
    # 1️⃣ Extract Campus → Schools → Departments → Users
    # ---------------------------------------------------
    coordinator_campus = user.campus

    # Keep ALL schools and ALL departments for THIS CAMPUS
    schools = School.objects.filter(campus=coordinator_campus)
    departments = Department.objects.filter(school__in=schools)
    campus_users = CustomUser.objects.filter(campus=coordinator_campus)

    # ---------------------------------------------------
    # 2️⃣ School Filter (but DO NOT overwrite schools list)
    # ---------------------------------------------------
    selected_school_id = request.GET.get("school")
    selected_school = None

    if selected_school_id:
        selected_school = schools.filter(id=selected_school_id).first()

    if selected_school:
        filtered_departments = departments.filter(school=selected_school)
        filtered_users = campus_users.filter(school=selected_school)
    else:
        filtered_departments = departments
        filtered_users = campus_users

    # ---------------------------------------------------
    # 3️⃣ Campus-Wide Project Query
    # ---------------------------------------------------
    projects_qs = Project.objects.filter(
        Q(created_by__in=filtered_users) |
        Q(tasks__assigned_to__in=filtered_users) |
        Q(teams__members__in=filtered_users) |
        Q(department__in=filtered_departments)
    ).distinct()

    # ---------------------------------------------------
    # 4️⃣ Persist Selected Project
    # ---------------------------------------------------
    if request.GET.get("project") is not None:
        request.session["selected_project_id"] = request.GET.get("project")

    selected_project_id = request.GET.get("project") or request.session.get("selected_project_id")
    current_project = projects_qs.filter(id=selected_project_id).first() if selected_project_id else None

    # ---------------------------------------------------
    # 5️⃣ Campus-Wide Tasks
    # ---------------------------------------------------
    tasks_qs = Task.objects.filter(
        Q(project__in=projects_qs) |
        Q(assigned_to__in=filtered_users) |
        Q(team__members__in=filtered_users)
    ).distinct()

    if current_project:
        tasks_qs = tasks_qs.filter(project=current_project)

    kanban_tasks = {
        "to_do": list(tasks_qs.filter(status="to_do")),
        "in_progress": list(tasks_qs.filter(status="in_progress")),
        "in_review": list(tasks_qs.filter(status="in_review")),
        "done": list(tasks_qs.filter(status="done")),
    }

    todo_count = len(kanban_tasks["to_do"])
    in_progress_count = len(kanban_tasks["in_progress"])
    in_review_count = len(kanban_tasks["in_review"])
    done_count = len(kanban_tasks["done"])

    completed_count = tasks_qs.filter(status="done", updated_at__gte=now - timedelta(days=7)).count()
    updated_count = tasks_qs.filter(updated_at__gte=now - timedelta(days=7)).count()
    created_count = tasks_qs.filter(created_at__gte=now - timedelta(days=7)).count()
    due_soon_count = tasks_qs.filter(
        due_date__lte=now + timedelta(days=7),
        due_date__gte=now,
        status__in=["to_do", "in_progress"]
    ).count()

    # ---------------------------------------------------
    # 6️⃣ Campus-Wide Teams
    # ---------------------------------------------------
    all_allowed_teams = Team.objects.filter(
        Q(project__in=projects_qs) |
        Q(members__in=filtered_users)
    ).distinct()

    teams = all_allowed_teams.filter(project=current_project) if current_project else all_allowed_teams

    # ---------------------------------------------------
    # 7️⃣ Staff + Students For Filters
    # ---------------------------------------------------
    staff_and_students = CustomUser.objects.filter(
        campus=coordinator_campus,
        role__in=["staff", "student"]
    ).order_by("email").distinct()

    # ---------------------------------------------------
    # 8️⃣ Project Status Analytics
    # ---------------------------------------------------
    total_projects = projects_qs.count()
    ongoing_projects = 0
    upcoming_projects = 0
    completed_projects = 0

    for project in projects_qs:
        status = get_project_status(project)
        if status == "ongoing":
            ongoing_projects += 1
        elif status == "upcoming":
            upcoming_projects += 1
        elif status == "completed":
            completed_projects += 1

    # ---------------------------------------------------
    # 9️⃣ Schools → Project Counts (use ALL schools)
    # ---------------------------------------------------
    schools_with_counts = []
    all_schools = School.objects.filter(campus=coordinator_campus)

    for school in all_schools:
        school_departments = Department.objects.filter(school=school)
        count = projects_qs.filter(department__in=school_departments).distinct().count()

        schools_with_counts.append({
            "id": school.id,
            "name": school.name,
            "project_count": count
        })

    # ---------------------------------------------------
    # 🔟 Departments → Project Counts
    # ---------------------------------------------------
    departments_with_counts = []
    for dept in filtered_departments:
        count = projects_qs.filter(department=dept).distinct().count()

        departments_with_counts.append({
            "id": dept.id,
            "name": dept.name,
            "school_name": dept.school.name,
            "project_count": count
        })

    # ---------------------------------------------------
    # 1️⃣1️⃣ Recent Projects (Campus-Wide)
    # ---------------------------------------------------
    recent_projects_list = []
    for project in projects_qs.order_by("-created_at")[:20]:
        school_name = (
            project.department.first().school.name
            if project.department.exists()
            else "No School"
        )
        recent_projects_list.append({
            "id": project.id,
            "name": project.name,
            "school": school_name,
            "start_date": project.start_date,
            "end_date": project.end_date,
            "status": get_project_status(project),
        })

    # ---------------------------------------------------
    # CONTEXT
    # ---------------------------------------------------
    context = {
        "active_tab": "summary",

        "kanban_tasks": kanban_tasks,
        "todo_count": todo_count,
        "in_progress_count": in_progress_count,
        "in_review_count": in_review_count,
        "done_count": done_count,
        "completed_count": completed_count,
        "updated_count": updated_count,
        "created_count": created_count,
        "due_soon_count": due_soon_count,

        "projects": projects_qs,
        "schools": schools_with_counts,
        "departments": departments_with_counts,
        "teams": teams,
        "current_project": current_project,
        "selected_school": selected_school,

        "total_projects": total_projects,
        "ongoing_projects": ongoing_projects,
        "upcoming_projects": upcoming_projects,
        "completed_projects": completed_projects,

        "total_departments": filtered_departments.count(),
        "total_schools": all_schools.count(),
        "total_teams": teams.count(),
        "recent_projects": recent_projects_list,

        "staff_and_students": staff_and_students,

        "is_read_only": True,
    }

    return render(request, "accounts/coordinator_dashboard.html", context)



def assign_coordinator_relations(user):
    if user.role == "coordinator" and user.campus:

        # Assign all schools under the campus
        schools = School.objects.filter(campus=user.campus)
        # If coordinator has no school assigned, assign one (optional)
        if not user.school:
            user.school = schools.first()
            user.save()

        # Assign all departments under the schools
        departments = Department.objects.filter(school__in=schools)
        user.department.set(departments)
