# Zero-Trust RBAC Web Application (Updated)

## Features
- Flask web application with role-based dashboards.
- Roles: Admin, Employee, Student, Guest, IT, HR, Finance, Sales, Marketing and Operations.
- SQLite persistence (`zero_trust.db`) instead of temporary in-memory user records.
- Password hashing using Werkzeug.
- Admin user creation, editing, deactivation and deletion.
- Users can update their own contact details but cannot change their own role or department.
- Guest profile is read-only.
- Admin-only audit log and user management.
- Demo IP-to-role mapping for the Packet Tracer VLAN host addresses.

## Requirements
- Python 3.10 or later
- Flask 3.x

Install:
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Run:
```powershell
python app.py
```
Open `http://127.0.0.1:5000`.

## Demo accounts
| Role | Username | Password |
|---|---|---|
| Admin | admin | admin123 |
| Employee | employee | employee123 |
| Student | student | student123 |
| Guest | guest | guest123 |
| IT | it_user | it123 |
| HR | hr_user | hr123 |
| Finance | finance_user | finance123 |
| Sales | sales_user | sales123 |
| Marketing | marketing_user | marketing123 |
| Operations | operations_user | operations123 |

Change these demo passwords before any real deployment. Set a strong `SECRET_KEY` environment variable.

## Packet Tracer mapping
| Role | VLAN | Example mapped PC IP |
|---|---:|---|
| Admin | 10 | 192.168.10.10 |
| Employee | 20 | 192.168.20.10 |
| Student | 30 | 192.168.30.10 |
| Guest | 50 | 192.168.50.10 |
| IT | 60 | 192.168.60.10 |
| HR | 61 | 192.168.61.10 |
| Finance | 62 | 192.168.62.10 |
| Sales | 63 | 192.168.63.10 |
| Marketing | 64 | 192.168.64.10 |
| Operations | 65 | 192.168.65.10 |

The IP mapping is a demonstration check, not cryptographic device identity. The app only sees the source IP that reaches the Flask host. Localhost is allowed for development so all demo accounts can be tested locally.

## Important project limitation
The Flask app and Cisco Packet Tracer topology are separate simulations unless you deliberately connect the Flask host/server to the Packet Tracer network and route traffic to it. This app does not automatically read router ACLs, VLAN configuration, or Packet Tracer state. The role mapping in `app.py` is an application-side demonstration, not live router integration.

## Data
The SQLite database is created automatically on first run and persists in `zero_trust.db`. Seed accounts are inserted only if their usernames do not already exist. To reset the demo database, stop Flask and delete `zero_trust.db`; the demo users will be recreated next run.


## Multiple demo users

The database is seeded with 3 demo accounts for each role (30 accounts total).
The original 10 demo accounts remain unchanged. Two additional accounts per role
are inserted with `INSERT OR IGNORE`, so running the updated app against an
existing `zero_trust.db` adds the new accounts without deleting existing users.

### Additional demo accounts

| Role | Username | Password |
|---|---|---|
| Admin | `admin2` | `admin2345` |
| Admin | `admin3` | `admin3456` |
| Employee | `employee2` | `employee2345` |
| Employee | `employee3` | `employee3456` |
| Student | `student2` | `student2345` |
| Student | `student3` | `student3456` |
| Guest | `guest2` | `guest2345` |
| Guest | `guest3` | `guest3456` |
| IT | `it_user2` | `ituser2345` |
| IT | `it_user3` | `ituser3456` |
| HR | `hr_user2` | `hruser2345` |
| HR | `hr_user3` | `hruser3456` |
| Finance | `finance_user2` | `finance2345` |
| Finance | `finance_user3` | `finance3456` |
| Sales | `sales_user2` | `salesuser2345` |
| Sales | `sales_user3` | `salesuser3456` |
| Marketing | `marketing_user2` | `market2345` |
| Marketing | `marketing_user3` | `market3456` |
| Operations | `operations_user2` | `opsuser2345` |
| Operations | `operations_user3` | `opsuser3456` |

These are demonstration credentials only. Change them before any real deployment.


## User count: 63 demo accounts

The application seeds **3 Admin accounts + 60 non-admin accounts = 63 total**.
The 60 non-admin accounts are distributed as follows:

| Role | Accounts |
|---|---:|
| Admin | 3 |
| Employee | 7 |
| Student | 7 |
| Guest | 6 |
| IT | 7 |
| HR | 7 |
| Finance | 7 |
| Sales | 7 |
| Marketing | 6 |
| Operations | 6 |
| **Total** | **63** |

The original 30 demo accounts and their passwords remain unchanged. New accounts
are added with `INSERT OR IGNORE`, so an existing `zero_trust.db` is preserved
and receives only missing accounts when the updated app starts.

### Additional accounts

For each role, accounts with suffixes 4 and onward are created up to the count
shown above. Their usernames follow the role's existing naming pattern:
`employee4`, `student4`, `guest4`, `it_user4`, `hr_user4`, `finance_user4`,
`sales_user4`, `marketing_user4`, and `operations_user4` (continuing to the
role-specific final suffix).

Their demo passwords follow the pattern `<role-password-prefix><number>demo`.
Examples: `employee4demo`, `ituser4demo`, `market4demo`, `opsuser4demo`.

These are demonstration credentials only. Change all demo passwords before
any real deployment.
