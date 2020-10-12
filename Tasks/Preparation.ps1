# This file will create a desktop folder with all necessary tools for the tasks

# Create Desktop folder structure
cd $home
cd .\Desktop\
mkdir tools
cd tools

# Install necessary tools
choco install git -y

# Download My AD Tool Collection
git clone https://github.com/helo86/Tools-AD

