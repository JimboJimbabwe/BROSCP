// Configuration options - MODIFY THESE
const CONFIG = {
  // Domain to target (empty = current domain)
  targetDomain: '', // Example: 'www.amazon.com'
  
  // Should the script include subdomains?
  includeSubdomains: false, // Set to true to include subdomains like 'smile.amazon.com'
  
  // Number of random links to select
  linksToSelect: 5,
  
  // Delay between opening links (milliseconds)
  openDelay: 300
};

// Function to check if a URL matches the target domain
function isDomainMatch(url) {
  // If no target domain is specified, use the current domain
  const targetDomain = CONFIG.targetDomain || window.location.hostname;
  
  // If including subdomains, check if the hostname ends with the target domain
  if (CONFIG.includeSubdomains) {
    return url.hostname === targetDomain || 
           url.hostname.endsWith('.' + targetDomain);
  }
  
  // Otherwise, check for exact domain match
  return url.hostname === targetDomain;
}

// Function to find links on the current page based on domain
function findDomainLinks() {
  // Get all anchor elements on the page
  const allLinks = Array.from(document.querySelectorAll('a'));
  
  // Get the current path for filtering out self-links
  const currentPath = window.location.pathname + window.location.search + window.location.hash;
  
  // Filter links based on domain criteria
  const domainLinks = allLinks.filter(link => {
    const href = link.getAttribute('href');
    
    // Skip links without href, javascript: links, or # links
    if (!href || href.startsWith('javascript:') || href === '#') {
      return false;
    }
    
    try {
      // Construct full URL
      const url = new URL(href, window.location.href);
      
      // Skip links to current page
      if (url.pathname + url.search + url.hash === currentPath) {
        return false;
      }
      
      // Check if the domain matches our target
      return isDomainMatch(url);
    } catch (e) {
      // Invalid URL
      console.error('Invalid URL:', href);
      return false;
    }
  });
  
  return domainLinks;
}

// Function to randomly select n links from an array
function selectRandomLinks(links, count) {
  // Clone the links array to avoid modifying the original
  const linksCopy = [...links];
  const selectedLinks = [];
  
  // Make sure we don't try to select more links than available
  const selectionCount = Math.min(count, linksCopy.length);
  
  // Randomly select links
  for (let i = 0; i < selectionCount; i++) {
    // Generate a random index
    const randomIndex = Math.floor(Math.random() * linksCopy.length);
    
    // Add the randomly selected link to our result
    selectedLinks.push(linksCopy[randomIndex]);
    
    // Remove the selected link from the copy to avoid duplicates
    linksCopy.splice(randomIndex, 1);
  }
  
  return selectedLinks;
}

// Function to visually highlight links on the page
function highlightLinks(allLinks, selectedLinks) {
  // First, let's highlight all links with a subtle outline
  allLinks.forEach(link => {
    // Save original styles to restore later
    link._originalOutline = link.style.outline;
    link._originalOutlineOffset = link.style.outlineOffset;
    link._originalTransition = link.style.transition;
    
    // Add a subtle blue outline to all domain links
    link.style.outline = '1px dashed rgba(0, 100, 255, 0.5)';
    link.style.outlineOffset = '2px';
    link.style.transition = 'all 0.3s ease-in-out';
  });
  
  // Then, highlight selected links with a more prominent style
  selectedLinks.forEach(link => {
    // Add a more prominent green outline to selected links
    link.style.outline = '3px solid rgba(0, 200, 0, 0.8)';
    link.style.outlineOffset = '3px';
    
    // Add pulse animation
    link.style.animation = 'pulse 1.5s infinite';
    
    // Create the pulse animation if it doesn't exist
    if (!document.getElementById('link-pulse-animation')) {
      const style = document.createElement('style');
      style.id = 'link-pulse-animation';
      style.textContent = `
        @keyframes pulse {
          0% { outline-color: rgba(0, 200, 0, 0.8); }
          50% { outline-color: rgba(0, 255, 0, 1); }
          100% { outline-color: rgba(0, 200, 0, 0.8); }
        }
      `;
      document.head.appendChild(style);
    }
  });
  
  // Create a function to restore original styles
  window.restoreLinkStyles = function() {
    allLinks.forEach(link => {
      link.style.outline = link._originalOutline || '';
      link.style.outlineOffset = link._originalOutlineOffset || '';
      link.style.transition = link._originalTransition || '';
      link.style.animation = '';
    });
    
    // Remove the animation style
    const animStyle = document.getElementById('link-pulse-animation');
    if (animStyle) {
      document.head.removeChild(animStyle);
    }
    
    console.log('Link highlighting removed');
  };
  
  // Add a restoration button
  const resetButton = document.createElement('button');
  resetButton.textContent = 'Remove Highlighting';
  resetButton.style.position = 'fixed';
  resetButton.style.bottom = '10px';
  resetButton.style.right = '10px';
  resetButton.style.zIndex = '10000';
  resetButton.style.padding = '8px 12px';
  resetButton.style.backgroundColor = '#f44336';
  resetButton.style.color = 'white';
  resetButton.style.border = 'none';
  resetButton.style.borderRadius = '4px';
  resetButton.style.cursor = 'pointer';
  
  resetButton.addEventListener('click', () => {
    window.restoreLinkStyles();
    document.body.removeChild(resetButton);
  });
  
  document.body.appendChild(resetButton);
  
  // Log instructions for manual removal
  console.log('To remove link highlighting manually, run: window.restoreLinkStyles()');
}

// Function to create a control panel for link management
function createControlPanel(links) {
  // Get URLs from links
  const urls = links.map(link => {
    const href = link.getAttribute('href');
    const url = new URL(href, window.location.href);
    return {
      url: url.href,
      domain: url.hostname,
      path: url.pathname + url.search,
      text: link.textContent.trim().substring(0, 30) || href
    };
  });
  
  // Create the panel
  const panel = document.createElement('div');
  panel.id = 'domain-walker-panel';
  panel.style.position = 'fixed';
  panel.style.top = '10px';
  panel.style.right = '10px';
  panel.style.zIndex = '10000';
  panel.style.backgroundColor = 'white';
  panel.style.padding = '10px';
  panel.style.border = '2px solid black';
  panel.style.borderRadius = '5px';
  panel.style.maxWidth = '400px';
  panel.style.maxHeight = '80vh';
  panel.style.overflowY = 'auto';
  panel.style.boxShadow = '0 4px 8px rgba(0,0,0,0.2)';
  
  // Add title
  const title = document.createElement('h3');
  title.textContent = 'Domain Auto-Walker';
  title.style.marginTop = '0';
  title.style.borderBottom = '1px solid #ccc';
  title.style.paddingBottom = '5px';
  panel.appendChild(title);
  
  // Add close button
  const closeButton = document.createElement('button');
  closeButton.textContent = '×';
  closeButton.style.position = 'absolute';
  closeButton.style.top = '5px';
  closeButton.style.right = '10px';
  closeButton.style.background = 'none';
  closeButton.style.border = 'none';
  closeButton.style.fontSize = '20px';
  closeButton.style.cursor = 'pointer';
  closeButton.addEventListener('click', () => document.body.removeChild(panel));
  panel.appendChild(closeButton);
  
  // Add domain configuration
  const domainSection = document.createElement('div');
  domainSection.style.marginBottom = '15px';
  
  const domainLabel = document.createElement('div');
  domainLabel.textContent = 'Target Domain:';
  domainLabel.style.fontWeight = 'bold';
  domainLabel.style.marginBottom = '5px';
  domainSection.appendChild(domainLabel);
  
  const domainInput = document.createElement('input');
  domainInput.type = 'text';
  domainInput.value = CONFIG.targetDomain || window.location.hostname;
  domainInput.style.width = '100%';
  domainInput.style.padding = '5px';
  domainInput.style.boxSizing = 'border-box';
  domainInput.addEventListener('change', () => {
    // Update the domain configuration
    CONFIG.targetDomain = domainInput.value.trim();
    // Refresh the panel
    refreshPanel();
  });
  domainSection.appendChild(domainInput);
  
  // Add subdomain checkbox
  const subdomainContainer = document.createElement('div');
  subdomainContainer.style.marginTop = '5px';
  
  const subdomainCheckbox = document.createElement('input');
  subdomainCheckbox.type = 'checkbox';
  subdomainCheckbox.id = 'subdomain-checkbox';
  subdomainCheckbox.checked = CONFIG.includeSubdomains;
  subdomainCheckbox.addEventListener('change', () => {
    CONFIG.includeSubdomains = subdomainCheckbox.checked;
    refreshPanel();
  });
  subdomainContainer.appendChild(subdomainCheckbox);
  
  const subdomainLabel = document.createElement('label');
  subdomainLabel.htmlFor = 'subdomain-checkbox';
  subdomainLabel.textContent = ' Include subdomains';
  subdomainLabel.style.marginLeft = '5px';
  subdomainContainer.appendChild(subdomainLabel);
  
  domainSection.appendChild(subdomainContainer);
  
  const refreshButton = document.createElement('button');
  refreshButton.textContent = 'Refresh Links';
  refreshButton.style.marginTop = '10px';
  refreshButton.style.padding = '5px';
  refreshButton.style.width = '100%';
  refreshButton.style.cursor = 'pointer';
  refreshButton.addEventListener('click', refreshPanel);
  domainSection.appendChild(refreshButton);
  
  panel.appendChild(domainSection);
  
  // Create links section
  const linksSection = document.createElement('div');
  linksSection.id = 'links-section';
  
  // Selected links counter
  const linksCountLabel = document.createElement('div');
  linksCountLabel.style.fontWeight = 'bold';
  linksCountLabel.style.marginBottom = '5px';
  linksSection.appendChild(linksCountLabel);
  
  // Create a button for each URL
  const linksList = document.createElement('div');
  linksSection.appendChild(linksList);
  
  // Add open all button
  const openAllButton = document.createElement('button');
  openAllButton.textContent = 'Open All Selected (One by One)';
  openAllButton.style.display = 'block';
  openAllButton.style.width = '100%';
  openAllButton.style.margin = '10px 0';
  openAllButton.style.padding = '8px';
  openAllButton.style.backgroundColor = '#4CAF50';
  openAllButton.style.color = 'white';
  openAllButton.style.border = 'none';
  openAllButton.style.borderRadius = '4px';
  openAllButton.style.cursor = 'pointer';
  
  openAllButton.addEventListener('click', () => {
    openAllButton.textContent = 'Opening...';
    openAllButton.disabled = true;
    
    let delay = 0;
    urls.forEach((urlInfo, index) => {
      setTimeout(() => {
        window.open(urlInfo.url, '_blank');
        openAllButton.textContent = `Opened ${index + 1}/${urls.length}...`;
        
        if (index === urls.length - 1) {
          setTimeout(() => {
            openAllButton.textContent = 'All Opened';
            setTimeout(() => {
              openAllButton.textContent = 'Open All Selected (One by One)';
              openAllButton.disabled = false;
            }, 2000);
          }, 500);
        }
      }, delay);
      delay += CONFIG.openDelay;
    });
  });
  
  linksSection.appendChild(openAllButton);
  panel.appendChild(linksSection);
  
  // Add custom settings section
  const settingsSection = document.createElement('div');
  settingsSection.style.borderTop = '1px solid #ccc';
  settingsSection.style.marginTop = '10px';
  settingsSection.style.paddingTop = '10px';
  
  const settingsTitle = document.createElement('div');
  settingsTitle.textContent = 'Settings';
  settingsTitle.style.fontWeight = 'bold';
  settingsTitle.style.marginBottom = '5px';
  settingsSection.appendChild(settingsTitle);
  
  // Links count selector
  const countLabel = document.createElement('label');
  countLabel.textContent = 'Number of links to select: ';
  settingsSection.appendChild(countLabel);
  
  const countInput = document.createElement('input');
  countInput.type = 'number';
  countInput.min = '1';
  countInput.max = '20';
  countInput.value = CONFIG.linksToSelect;
  countInput.style.width = '60px';
  countInput.addEventListener('change', () => {
    CONFIG.linksToSelect = parseInt(countInput.value, 10) || 5;
    refreshPanel();
  });
  settingsSection.appendChild(countInput);
  
  settingsSection.appendChild(document.createElement('br'));
  
  // Delay selector
  const delayLabel = document.createElement('label');
  delayLabel.textContent = 'Delay between opening links (ms): ';
  settingsSection.appendChild(delayLabel);
  
  const delayInput = document.createElement('input');
  delayInput.type = 'number';
  delayInput.min = '100';
  delayInput.max = '2000';
  delayInput.step = '100';
  delayInput.value = CONFIG.openDelay;
  delayInput.style.width = '60px';
  delayInput.addEventListener('change', () => {
    CONFIG.openDelay = parseInt(delayInput.value, 10) || 300;
  });
  settingsSection.appendChild(delayInput);
  
  panel.appendChild(settingsSection);
  
  // Function to refresh the panel with updated settings
  function refreshPanel() {
    // Get updated links based on domain
    const allLinks = findDomainLinks();
    const selectedLinks = selectRandomLinks(allLinks, CONFIG.linksToSelect);
    
    // Remove old highlighted styles if they exist
    if (window.restoreLinkStyles) {
      window.restoreLinkStyles();
    }
    
    // Apply new highlighting
    highlightLinks(allLinks, selectedLinks);
    
    // Update URL list
    const urls = selectedLinks.map(link => {
      const href = link.getAttribute('href');
      const url = new URL(href, window.location.href);
      return {
        url: url.href,
        domain: url.hostname,
        path: url.pathname + url.search,
        text: link.textContent.trim().substring(0, 30) || href
      };
    });
    
    // Current domain info
    const domainInfo = document.createElement('div');
    domainInfo.innerHTML = `<small>Current page domain: <strong>${window.location.hostname}</strong></small>`;
    domainInfo.style.marginBottom = '10px';
    domainInfo.style.fontStyle = 'italic';
    
    // Update the links count label
    linksCountLabel.textContent = `Selected Links (${selectedLinks.length} of ${allLinks.length} available):`;
    
    // Clear existing link buttons
    linksList.innerHTML = '';
    linksList.appendChild(domainInfo);
    
    // Create link buttons
    urls.forEach((urlInfo, index) => {
      const linkContainer = document.createElement('div');
      linkContainer.style.display = 'flex';
      linkContainer.style.margin = '5px 0';
      linkContainer.style.padding = '5px';
      linkContainer.style.backgroundColor = '#f8f8f8';
      linkContainer.style.borderRadius = '3px';
      
      const linkButton = document.createElement('button');
      linkButton.textContent = `${index + 1}`;
      linkButton.style.marginRight = '5px';
      linkButton.style.padding = '2px 6px';
      linkButton.style.cursor = 'pointer';
      linkButton.addEventListener('click', () => window.open(urlInfo.url, '_blank'));
      linkContainer.appendChild(linkButton);
      
      const linkText = document.createElement('div');
      linkText.innerHTML = `<div>${urlInfo.text || 'Link'}</div><small>${urlInfo.domain}${urlInfo.path}</small>`;
      linkText.style.overflow = 'hidden';
      linkText.style.textOverflow = 'ellipsis';
      linkText.style.whiteSpace = 'nowrap';
      linkText.style.flex = '1';
      linkContainer.appendChild(linkText);
      
      linksList.appendChild(linkContainer);
    });
    
    console.log(`Found ${allLinks.length} links for domain ${CONFIG.targetDomain || window.location.hostname}, selected ${selectedLinks.length}`);
  }
  
  // Add to page
  document.body.appendChild(panel);
  
  // Initial refresh
  refreshPanel();
  
  return panel;
}

// Main function to start the domain walker
function startDomainWalker() {
  // Find domain-scoped links
  const allLinks = findDomainLinks();
  
  // Log the number of links found
  console.log(`Found ${allLinks.length} links on domain: ${CONFIG.targetDomain || window.location.hostname}`);
  
  if (allLinks.length === 0) {
    console.log('No links found for the target domain');
    alert(`No links found for domain: ${CONFIG.targetDomain || window.location.hostname}`);
    return;
  }
  
  // Select random links
  const randomLinks = selectRandomLinks(allLinks, CONFIG.linksToSelect);
  
  // Highlight all links on the page
  highlightLinks(allLinks, randomLinks);
  
  // Create the control panel
  createControlPanel(randomLinks);
  
  return {
    allLinks,
    selectedLinks: randomLinks
  };
}

// Start the domain walker
startDomainWalker();
