# Project Links

A Flask-based web application for managing and organizing collections of links grouped into categories. Features an admin panel for configuration, authentication, and security settings. Supports deployment via Ansible with Docker or bare-metal options.

## Features

- **Link Management**: Organize links into customizable groups with titles, descriptions, and URLs
- **Admin Panel**: Web-based interface for managing groups, links, and application settings
- **Authentication**: Password-protected admin access with session management
- **Security Features**:
  - CSRF protection
  - IP address restrictions
  - Session timeout (30 minutes)
- **Customization**: Configurable colors, fonts, logo, and UI themes
- **Data Storage**: JSON-based storage for easy backup and portability
- **Deployment**: Ansible playbooks for automated deployment with Docker or bare-metal

## Design Philosophy

The project was intentionally designed to be as simple as possible, without a database. If you need database functionality, you can either implement it yourself or contact the author for paid customizations.

## Project Structure

- `app.py`: Main Flask application
- `requirements.txt`: Python dependencies
- `templates/`: Jinja2 templates
- `static/`: Static assets
- `data.json`: Application data storage
- `app/`: Docker-related files (Dockerfile, docker-compose.yml)
- `deploy/`: Ansible deployment files (inventory.yml, playbook.yml)
- `.env`: Environment variables and secrets

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/alex-lik/project-links.git
   cd project-links
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

### Development
Start the development server:
```bash
python app.py
```
The application will be available at `http://localhost:5000`

### Production Deployment

#### Using Ansible
1. Update `.env` with your secrets and server details
2. Update `deploy/inventory.yml` if needed
3. Set `use_docker: true` in `deploy/playbook.yml` for Docker deployment or `false` for bare-metal
4. Run the playbook:
   ```bash
   cd deploy
   ansible-playbook -i inventory.yml playbook.yml
   ```

#### Using Docker Compose
```bash
cd app
docker-compose up -d
```

## Default Credentials
- **Username**: admin
- **Password**: admin (change after first login)

## Usage

### Public Interface
- View organized links by groups
- Click on links to navigate to external sites

### Admin Panel
Access the admin panel at `/admin` after logging in.

#### Managing Groups
- Add new groups with custom background colors
- Edit group names and colors
- Delete groups

#### Managing Links
- Add links to groups with title, URL, and description
- Edit link details
- Delete links

#### Settings
- **General**: Title, logo, colors, fonts
- **Security**: Enable authentication, set IP restrictions
- **Password**: Change admin password

## Configuration

Settings are stored in `data.json`. The application automatically creates default settings on first run.

Key configuration options:
- `auth_only`: Require authentication for all pages
- `allowed_ips`: List of allowed IP addresses
- `primary_color`, `hover_color`, etc.: UI customization
- `password_hash`: Hashed admin password

Environment variables in `.env`:
- `SECRET_KEY`: Flask secret key
- `SERVER_IP`: Server IP for Ansible
- `SERVER_USER`: SSH user for Ansible

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and commit: `git commit -am 'Add feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
