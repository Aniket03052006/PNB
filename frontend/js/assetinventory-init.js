/**
 * Asset Inventory Initialization Module
 * Integrates Asset Inventory with Q-ARMOR Dashboard
 */

(function initializeAssetInventoryModule() {
    // Export the initialization function to window
    window.initializeAssetInventory = function initializeAssetInventory() {
        const container = document.getElementById('asset-inventory-container');
        if (!container) {
            console.warn('Asset inventory container not found');
            return;
        }

        // Create the asset inventory UI structure
        container.innerHTML = `
            <div class="panel" style="margin-bottom: 20px;">
                <div class="panel-header">
                    <div class="panel-title">
                        <span class="material-symbols-outlined" style="font-size: 1.2rem;">inventory_2</span> Asset Inventory Manager
                    </div>
                </div>
                
                <!-- Stats Grid -->
                <div class="stats-grid" id="statsGrid" style="margin-bottom: 24px;"></div>
                
                <!-- Search and Filters -->
                <div class="scan-input-section" style="padding: 0 0 16px 0;">
                    <input type="text" id="searchInput" class="scan-input" placeholder="Search assets...">
                    <select id="filterType" class="scan-input" style="max-width: 150px;">
                        <option value="">All Types</option>
                        <option value="web app">Web App</option>
                        <option value="api">API</option>
                        <option value="server">Server</option>
                        <option value="gateway">Gateway</option>
                    </select>
                    <select id="filterRisk" class="scan-input" style="max-width: 150px;">
                        <option value="">All Risk Levels</option>
                        <option value="low">Low Risk</option>
                        <option value="medium">Medium Risk</option>
                        <option value="high">High Risk</option>
                        <option value="critical">Critical</option>
                    </select>
                    <button class="btn btn-primary" onclick="invScanAllAssets()"><span class="material-symbols-outlined" style="font-size: 16px;">radar</span> Scan Selected</button>
                    <button class="btn" onclick="invResolveDomain()"><span class="material-symbols-outlined" style="font-size: 16px;">public</span> Resolve DNS</button>
                </div>
                
                <!-- Asset Inventory Table -->
                <div style="overflow-x: auto; margin-bottom: 10px;">
                    <div id="inventoryBody"></div>
                </div>
            </div>

            <div class="main-grid">
                <!-- Nameserver Records Panel -->
                <div class="panel" style="margin-bottom: 0;">
                    <div class="panel-header">
                        <div class="panel-title"><span class="material-symbols-outlined" style="font-size: 1.1rem;">dns</span> Nameserver Records</div>
                    </div>
                    <div id="nameserverTable" style="overflow-x: auto;"></div>
                </div>
                
                <!-- Activity Feed Panel -->
                <div class="panel" style="margin-bottom: 0;">
                    <div class="panel-header">
                        <div class="panel-title"><span class="material-symbols-outlined" style="font-size: 1.1rem;">history</span> Recent Activity</div>
                    </div>
                    <div id="activityFeed"></div>
                </div>
            </div>

            <div class="panel" style="margin-top: 20px;">
                <div class="panel-header">
                    <div class="panel-title"><span class="material-symbols-outlined" style="font-size: 1.1rem;">enhanced_encryption</span> Cryptographic Security Overview</div>
                </div>
                <div id="cryptoOverviewBody" style="overflow-x: auto;"></div>
            </div>
        `;
        
        // Initialize state variables with defensive checks
        if (typeof window.allAssets === 'undefined' || !window.allAssets) {
            window.allAssets = [];
            window.filteredAssets = [];
            window.selectedAssets = new Set();
        }
        
        // Safely copy sample data with logging
        console.log('Initializing asset inventory...', {
            hasSampleAssets: !!window.SAMPLE_ASSETS,
            isArray: Array.isArray(window.SAMPLE_ASSETS),
            length: window.SAMPLE_ASSETS?.length
        });
        
        window.allAssets = (window.SAMPLE_ASSETS && Array.isArray(window.SAMPLE_ASSETS)) ? Array.from(window.SAMPLE_ASSETS) : [];
        window.filteredAssets = (window.SAMPLE_ASSETS && Array.isArray(window.SAMPLE_ASSETS)) ? Array.from(window.SAMPLE_ASSETS) : [];
        window.selectedAssets = new Set();
        
        console.log('Asset inventory state initialized:', {
            allAssetsLength: window.allAssets.length,
            filteredAssetsLength: window.filteredAssets.length
        });
        
        // Render all components
        try {
            if (typeof invRenderStatsCards === 'function') invRenderStatsCards();
            if (typeof invRenderAssetTable === 'function') invRenderAssetTable();
            if (typeof invRenderNameserverRecords === 'function') invRenderNameserverRecords();
            if (typeof invRenderCryptoOverview === 'function') invRenderCryptoOverview();
            if (typeof invRenderMapWithLegend === 'function') invRenderMapWithLegend();
            if (typeof invRenderActivityFeed === 'function') invRenderActivityFeed();
            if (typeof invAttachEventListeners === 'function') invAttachEventListeners();
        } catch (error) {
            console.error('Error initializing asset inventory components:', error);
            if (typeof invShowToast === 'function') {
                invShowToast('Failed to initialize asset inventory: ' + error.message, 'error');
            }
        }
    };

})();
