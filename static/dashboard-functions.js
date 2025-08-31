// ========================================
// USER CREATION & DOMAIN FUNCTIONS (TAB 2)
// ========================================

function createSingleUser() {
    const firstName = document.getElementById('new-user-first-name').value.trim();
    const lastName = document.getElementById('new-user-last-name').value.trim();
    const email = document.getElementById('new-user-email').value.trim();
    const password = document.getElementById('new-user-password').value.trim();
    
    if (!firstName || !lastName || !email || !password) {
        alert('Please fill in all fields');
        return;
    }
    
    if (!isAuthenticated) {
        alert('Please authenticate an account first');
        return;
    }
    
    fetch('/api/create_user', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            first_name: firstName,
            last_name: lastName,
            email: email,
            password: password
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            alert('User created successfully');
            // Clear form
            document.getElementById('new-user-first-name').value = '';
            document.getElementById('new-user-last-name').value = '';
            document.getElementById('new-user-email').value = '';
            document.getElementById('new-user-password').value = '';
        } else {
            alert(`Failed to create user: ${data.message}`);
        }
    })
    .catch(error => {
        alert(`Error: ${error.message}`);
    });
}

function getDomainInfo() {
    if (!isAuthenticated) {
        alert('Please authenticate an account first');
        return;
    }
    
    const domainDisplay = document.getElementById('domain-info-display');
    domainDisplay.innerHTML = '<p>Loading domain information...</p>';
    
    fetch('/api/get_domains', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            displayDomainInfo(data.domains);
        } else {
            domainDisplay.innerHTML = `<p class="status-error">Error: ${data.message}</p>`;
        }
    })
    .catch(error => {
        domainDisplay.innerHTML = `<p class="status-error">Error: ${error.message}</p>`;
    });
}

function displayDomainInfo(domains) {
    const domainDisplay = document.getElementById('domain-info-display');
    let html = '<div>';
    
    domains.forEach(domain => {
        const status = domain.verified ? 'Verified' : 'Not Verified';
        const statusClass = domain.verified ? 'status-success' : 'status-warning';
        
        html += `
            <div style="border: 1px solid var(--color-border-default); padding: 12px; margin: 8px 0; border-radius: 6px;">
                <strong>${domain.domainName}</strong><br>
                <span class="${statusClass}">${status}</span>
                ${domain.isPrimary ? ' <span class="badge badge-primary">Primary</span>' : ''}
            </div>
        `;
    });
    
    html += '</div>';
    domainDisplay.innerHTML = html;
}

function addDomainAlias() {
    const domainAlias = document.getElementById('new-domain-alias').value.trim();
    
    if (!domainAlias) {
        alert('Please enter a domain alias');
        return;
    }
    
    if (!isAuthenticated) {
        alert('Please authenticate an account first');
        return;
    }
    
    fetch('/api/add_domain_alias', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            domain_alias: domainAlias
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            alert('Domain alias added successfully');
            document.getElementById('new-domain-alias').value = '';
            getDomainInfo();
        } else {
            alert(`Failed to add domain alias: ${data.message}`);
        }
    })
    .catch(error => {
        alert(`Error: ${error.message}`);
    });
}

function createUsersFromCSV() {
    const fileInput = document.getElementById('csv-file-input');
    const file = fileInput.files[0];
    
    if (!file) {
        alert('Please select a CSV file');
        return;
    }
    
    if (!isAuthenticated) {
        alert('Please authenticate an account first');
        return;
    }
    
    const formData = new FormData();
    formData.append('csv_file', file);
    
    fetch('/api/create_users_csv', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            alert(`Successfully created ${data.created_count} users`);
            fileInput.value = '';
        } else {
            alert(`Failed to create users: ${data.message}`);
        }
    })
    .catch(error => {
        alert(`Error: ${error.message}`);
    });
}

function createRandomUsers() {
    const userCount = document.getElementById('random-user-count').value;
    const domain = document.getElementById('random-user-domain').value.trim();
    
    if (!userCount || !domain) {
        alert('Please fill in user count and domain');
        return;
    }
    
    if (!isAuthenticated) {
        alert('Please authenticate an account first');
        return;
    }
    
    fetch('/api/create_random_users', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            user_count: parseInt(userCount),
            domain: domain
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            alert(`Successfully created ${data.created_count} random users`);
            document.getElementById('random-user-count').value = '';
            document.getElementById('random-user-domain').value = '';
        } else {
            alert(`Failed to create users: ${data.message}`);
        }
    })
    .catch(error => {
        alert(`Error: ${error.message}`);
    });
}

function changeDomainForUsers() {
    const oldDomain = document.getElementById('old-domain').value.trim();
    const newDomain = document.getElementById('new-domain').value.trim();
    const emails = document.getElementById('domain-change-emails').value.trim();
    
    if (!oldDomain || !newDomain || !emails) {
        alert('Please fill in all fields');
        return;
    }
    
    if (!isAuthenticated) {
        alert('Please authenticate an account first');
        return;
    }
    
    const emailList = emails.split('\n').filter(email => email.trim());
    
    fetch('/api/change_domain_users', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            old_domain: oldDomain,
            new_domain: newDomain,
            emails: emailList
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            alert(`Successfully changed domain for ${data.updated_count} users`);
            // Clear form
            document.getElementById('old-domain').value = '';
            document.getElementById('new-domain').value = '';
            document.getElementById('domain-change-emails').value = '';
        } else {
            alert(`Failed to change domains: ${data.message}`);
        }
    })
    .catch(error => {
        alert(`Error: ${error.message}`);
    });
}

function deleteSpecificUsers() {
    const emails = document.getElementById('delete-user-emails').value.trim();
    
    if (!emails) {
        alert('Please enter email addresses to delete');
        return;
    }
    
    if (!isAuthenticated) {
        alert('Please authenticate an account first');
        return;
    }
    
    const emailList = emails.split('\n').filter(email => email.trim());
    
    if (confirm(`Are you sure you want to delete ${emailList.length} users? This action cannot be undone.`)) {
        fetch('/api/delete_users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                emails: emailList
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                alert(`Successfully deleted ${data.deleted_count} users`);
                document.getElementById('delete-user-emails').value = '';
            } else {
                alert(`Failed to delete users: ${data.message}`);
            }
        })
        .catch(error => {
            alert(`Error: ${error.message}`);
        });
    }
}

function clearResultsLog() {
    const resultsLog = document.getElementById('results-log');
    if (resultsLog) {
        resultsLog.innerHTML = '';
    }
}

function copyResultsLog() {
    const resultsLog = document.getElementById('results-log');
    if (resultsLog && navigator.clipboard) {
        navigator.clipboard.writeText(resultsLog.textContent).then(() => {
            alert('Results log copied to clipboard');
        });
    } else {
        alert('Clipboard not supported or no content to copy');
    }
}

// ========================================
// BULK DOMAIN CHANGE FUNCTIONS (TAB 3)
// ========================================

function downloadAllUsersCSV() {
    if (!isAuthenticated) {
        alert('Please authenticate an account first');
        return;
    }
    
    fetch('/api/download_users_csv', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            alert('Users CSV downloaded successfully');
            const csvPathInput = document.getElementById('csv-file-path');
            if (csvPathInput) {
                csvPathInput.value = data.filepath;
            }
        } else {
            alert(`Failed to download CSV: ${data.message}`);
        }
    })
    .catch(error => {
        alert(`Error: ${error.message}`);
    });
}

function retrieveAvailableDomains() {
    if (!isAuthenticated) {
        alert('Please authenticate an account first');
        return;
    }
    
    const domainsDisplay = document.getElementById('available-domains');
    domainsDisplay.innerHTML = '<p>Loading available domains...</p>';
    
    fetch('/api/get_available_domains', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            displayAvailableDomains(data.domains);
        } else {
            domainsDisplay.innerHTML = `<p class="status-error">Error: ${data.message}</p>`;
        }
    })
    .catch(error => {
        domainsDisplay.innerHTML = `<p class="status-error">Error: ${error.message}</p>`;
    });
}

function displayAvailableDomains(domains) {
    const domainsDisplay = document.getElementById('available-domains');
    let html = '<div><h4>Available Domains (click to select):</h4>';
    
    domains.forEach(domain => {
        html += `
            <div class="domain-item" onclick="selectDomain('${domain.domainName}')" 
                 style="border: 1px solid var(--color-border-default); padding: 10px; margin: 4px 0; 
                        border-radius: 4px; cursor: pointer; transition: background-color 0.2s;">
                <strong>${domain.domainName}</strong>
                ${domain.isPrimary ? ' <span class="badge badge-primary">Primary</span>' : ''}
                ${domain.verified ? ' <span class="badge badge-success">Verified</span>' : ' <span class="badge badge-warning">Not Verified</span>'}
            </div>
        `;
    });
    
    html += '</div>';
    domainsDisplay.innerHTML = html;
}

function selectDomain(domainName) {
    selectedDomain = domainName;
    
    // Update visual selection
    const domainItems = document.querySelectorAll('.domain-item');
    domainItems.forEach(item => {
        item.style.backgroundColor = 'transparent';
        item.style.borderColor = 'var(--color-border-default)';
        item.style.color = 'var(--color-fg-default)';
    });
    
    event.target.style.backgroundColor = 'var(--color-accent-emphasis)';
    event.target.style.borderColor = 'var(--color-accent-emphasis)';
    event.target.style.color = '#ffffff';
    
    alert(`Selected domain: ${domainName}`);
    console.log('Selected domain:', domainName);
}

function getDomainUsageStats() {
    if (!isAuthenticated) {
        alert('Please authenticate an account first');
        return;
    }
    
    fetch('/api/get_domain_stats', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            let message = 'Domain Usage Statistics:\n\n';
            for (const [domain, count] of Object.entries(data.stats)) {
                message += `${domain}: ${count} users\n`;
            }
            alert(message);
        } else {
            alert(`Failed to get domain stats: ${data.message}`);
        }
    })
    .catch(error => {
        alert(`Error: ${error.message}`);
    });
}

function clearOldDomainData() {
    const domainsDisplay = document.getElementById('available-domains');
    domainsDisplay.innerHTML = `
        <div class="status-info">
            <p><strong><i class="fas fa-globe"></i> Domain Selection</strong></p>
            <p>Click 'Retrieve Available Domains' to view available domains</p>
        </div>
    `;
    selectedDomain = null;
}

function applySelectedDomainToCSV() {
    if (!selectedDomain) {
        alert('Please select a domain first');
        return;
    }
    
    const csvPath = document.getElementById('csv-file-path').value.trim();
    if (!csvPath) {
        alert('Please download users CSV first or browse for a CSV file');
        return;
    }
    
    fetch('/api/apply_domain_to_csv', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            csv_path: csvPath,
            new_domain: selectedDomain
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            alert(`Domain ${selectedDomain} applied to CSV successfully`);
            document.getElementById('csv-file-path').value = data.new_csv_path;
        } else {
            alert(`Failed to apply domain: ${data.message}`);
        }
    })
    .catch(error => {
        alert(`Error: ${error.message}`);
    });
}

function debugDomainUsers() {
    if (!isAuthenticated) {
        alert('Please authenticate an account first');
        return;
    }
    
    fetch('/api/debug_domain_users', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        console.log('Debug data:', data);
        alert('Debug information logged to console');
    })
    .catch(error => {
        alert(`Debug error: ${error.message}`);
    });
}

function browseCSVFile() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.csv';
    input.onchange = function(e) {
        const file = e.target.files[0];
        if (file) {
            document.getElementById('csv-file-path').value = file.name;
        }
    };
    input.click();
}

function processDomainChangesFromCSV() {
    const csvPath = document.getElementById('csv-file-path').value.trim();
    
    if (!csvPath) {
        alert('Please specify a CSV file path');
        return;
    }
    
    if (!isAuthenticated) {
        alert('Please authenticate an account first');
        return;
    }
    
    const resultsDiv = document.getElementById('bulk-domain-results');
    resultsDiv.innerHTML = '<p>Processing domain changes from CSV...</p>';
    
    fetch('/api/process_domain_changes_csv', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            csv_path: csvPath
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            displayBulkDomainResults(data.results);
        } else {
            resultsDiv.innerHTML = `<p class="status-error">Error: ${data.message}</p>`;
        }
    })
    .catch(error => {
        resultsDiv.innerHTML = `<p class="status-error">Error: ${error.message}</p>`;
    });
}

function changeDomainForAllUsers() {
    const currentDomain = document.getElementById('current-domain-suffix').value.trim();
    const newDomain = document.getElementById('new-domain-suffix').value.trim();
    
    if (!currentDomain || !newDomain) {
        alert('Please fill in both current and new domain');
        return;
    }
    
    if (!isAuthenticated) {
        alert('Please authenticate an account first');
        return;
    }
    
    if (confirm(`Are you sure you want to change ALL users from ${currentDomain} to ${newDomain}? This will exclude admin users.`)) {
        const resultsDiv = document.getElementById('bulk-domain-results');
        resultsDiv.innerHTML = '<p>Processing bulk domain change...</p>';
        
        fetch('/api/bulk_domain_change', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                current_domain: currentDomain,
                new_domain: newDomain
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                displayBulkDomainResults(data.results);
            } else {
                resultsDiv.innerHTML = `<p class="status-error">Error: ${data.message}</p>`;
            }
        })
        .catch(error => {
            resultsDiv.innerHTML = `<p class="status-error">Error: ${error.message}</p>`;
        });
    }
}

function displayBulkDomainResults(results) {
    const resultsDiv = document.getElementById('bulk-domain-results');
    let html = '<div style="font-family: monospace; font-size: 13px; max-height: 400px; overflow-y: auto;">';
    
    if (results.success && results.success.length > 0) {
        html += '<h4 style="color: var(--color-success-fg);">Successful Changes:</h4>';
        results.success.forEach(result => {
            html += `<div style="color: var(--color-success-fg);">✅ ${result}</div>`;
        });
    }
    
    if (results.errors && results.errors.length > 0) {
        html += '<h4 style="color: var(--color-danger-fg);">Errors:</h4>';
        results.errors.forEach(error => {
            html += `<div style="color: var(--color-danger-fg);">❌ ${error}</div>`;
        });
    }
    
    html += '</div>';
    resultsDiv.innerHTML = html;
}

function clearBulkDomainLog() {
    const resultsDiv = document.getElementById('bulk-domain-results');
    resultsDiv.innerHTML = `
        <div class="status-info">
            <p><strong><i class="fas fa-file-alt"></i> Processing Results</strong></p>
            <p>Processing results will appear here...</p>
        </div>
    `;
}

// ========================================
// OAUTH MODAL FUNCTIONS
// ========================================

function closeOAuthModal() {
    const modal = document.getElementById('oauthModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

function copyOAuthUrl() {
    const urlDiv = document.getElementById('oauthUrl');
    if (urlDiv && navigator.clipboard) {
        navigator.clipboard.writeText(urlDiv.textContent).then(() => {
            alert('OAuth URL copied to clipboard');
        });
    }
}

function openOAuthUrl() {
    const urlDiv = document.getElementById('oauthUrl');
    if (urlDiv) {
        window.open(urlDiv.textContent, '_blank');
    }
}

console.log('Additional dashboard functions loaded successfully');
