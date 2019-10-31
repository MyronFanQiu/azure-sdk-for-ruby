# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

require 'uri'
require 'cgi'
require 'date'
require 'json'
require 'base64'
require 'erb'
require 'securerandom'
require 'time'
require 'timeliness'
require 'faraday'
require 'faraday-cookie_jar'
require 'concurrent'
require 'ms_rest'
require '2019-06-01/generated/azure_mgmt_storage/module_definition'
require 'ms_rest_azure'

module Azure::Storage::Mgmt::V2019_06_01
  autoload :Operations,                                         '2019-06-01/generated/azure_mgmt_storage/operations.rb'
  autoload :Skus,                                               '2019-06-01/generated/azure_mgmt_storage/skus.rb'
  autoload :StorageAccounts,                                    '2019-06-01/generated/azure_mgmt_storage/storage_accounts.rb'
  autoload :Usages,                                             '2019-06-01/generated/azure_mgmt_storage/usages.rb'
  autoload :ManagementPolicies,                                 '2019-06-01/generated/azure_mgmt_storage/management_policies.rb'
  autoload :PrivateEndpointConnections,                         '2019-06-01/generated/azure_mgmt_storage/private_endpoint_connections.rb'
  autoload :PrivateLinkResources,                               '2019-06-01/generated/azure_mgmt_storage/private_link_resources.rb'
  autoload :BlobServices,                                       '2019-06-01/generated/azure_mgmt_storage/blob_services.rb'
  autoload :BlobContainers,                                     '2019-06-01/generated/azure_mgmt_storage/blob_containers.rb'
  autoload :FileServices,                                       '2019-06-01/generated/azure_mgmt_storage/file_services.rb'
  autoload :FileShares,                                         '2019-06-01/generated/azure_mgmt_storage/file_shares.rb'
  autoload :StorageManagementClient,                            '2019-06-01/generated/azure_mgmt_storage/storage_management_client.rb'

  module Models
    autoload :ListServiceSasResponse,                             '2019-06-01/generated/azure_mgmt_storage/models/list_service_sas_response.rb'
    autoload :OperationDisplay,                                   '2019-06-01/generated/azure_mgmt_storage/models/operation_display.rb'
    autoload :DateAfterModification,                              '2019-06-01/generated/azure_mgmt_storage/models/date_after_modification.rb'
    autoload :MetricSpecification,                                '2019-06-01/generated/azure_mgmt_storage/models/metric_specification.rb'
    autoload :ManagementPolicyBaseBlob,                           '2019-06-01/generated/azure_mgmt_storage/models/management_policy_base_blob.rb'
    autoload :Operation,                                          '2019-06-01/generated/azure_mgmt_storage/models/operation.rb'
    autoload :DateAfterCreation,                                  '2019-06-01/generated/azure_mgmt_storage/models/date_after_creation.rb'
    autoload :StorageAccountCheckNameAvailabilityParameters,      '2019-06-01/generated/azure_mgmt_storage/models/storage_account_check_name_availability_parameters.rb'
    autoload :ManagementPolicySnapShot,                           '2019-06-01/generated/azure_mgmt_storage/models/management_policy_snap_shot.rb'
    autoload :Restriction,                                        '2019-06-01/generated/azure_mgmt_storage/models/restriction.rb'
    autoload :ManagementPolicyAction,                             '2019-06-01/generated/azure_mgmt_storage/models/management_policy_action.rb'
    autoload :StorageSkuListResult,                               '2019-06-01/generated/azure_mgmt_storage/models/storage_sku_list_result.rb'
    autoload :ManagementPolicyFilter,                             '2019-06-01/generated/azure_mgmt_storage/models/management_policy_filter.rb'
    autoload :CustomDomain,                                       '2019-06-01/generated/azure_mgmt_storage/models/custom_domain.rb'
    autoload :ManagementPolicyDefinition,                         '2019-06-01/generated/azure_mgmt_storage/models/management_policy_definition.rb'
    autoload :EncryptionServices,                                 '2019-06-01/generated/azure_mgmt_storage/models/encryption_services.rb'
    autoload :ManagementPolicyRule,                               '2019-06-01/generated/azure_mgmt_storage/models/management_policy_rule.rb'
    autoload :Encryption,                                         '2019-06-01/generated/azure_mgmt_storage/models/encryption.rb'
    autoload :ManagementPolicySchema,                             '2019-06-01/generated/azure_mgmt_storage/models/management_policy_schema.rb'
    autoload :IPRule,                                             '2019-06-01/generated/azure_mgmt_storage/models/iprule.rb'
    autoload :Sku,                                                '2019-06-01/generated/azure_mgmt_storage/models/sku.rb'
    autoload :ActiveDirectoryProperties,                          '2019-06-01/generated/azure_mgmt_storage/models/active_directory_properties.rb'
    autoload :CheckNameAvailabilityResult,                        '2019-06-01/generated/azure_mgmt_storage/models/check_name_availability_result.rb'
    autoload :Identity,                                           '2019-06-01/generated/azure_mgmt_storage/models/identity.rb'
    autoload :EncryptionService,                                  '2019-06-01/generated/azure_mgmt_storage/models/encryption_service.rb'
    autoload :Endpoints,                                          '2019-06-01/generated/azure_mgmt_storage/models/endpoints.rb'
    autoload :KeyVaultProperties,                                 '2019-06-01/generated/azure_mgmt_storage/models/key_vault_properties.rb'
    autoload :PrivateEndpoint,                                    '2019-06-01/generated/azure_mgmt_storage/models/private_endpoint.rb'
    autoload :VirtualNetworkRule,                                 '2019-06-01/generated/azure_mgmt_storage/models/virtual_network_rule.rb'
    autoload :PrivateLinkServiceConnectionState,                  '2019-06-01/generated/azure_mgmt_storage/models/private_link_service_connection_state.rb'
    autoload :CorsRules,                                          '2019-06-01/generated/azure_mgmt_storage/models/cors_rules.rb'
    autoload :StorageAccountKey,                                  '2019-06-01/generated/azure_mgmt_storage/models/storage_account_key.rb'
    autoload :NetworkRuleSet,                                     '2019-06-01/generated/azure_mgmt_storage/models/network_rule_set.rb'
    autoload :StorageAccountListKeysResult,                       '2019-06-01/generated/azure_mgmt_storage/models/storage_account_list_keys_result.rb'
    autoload :StorageAccountUpdateParameters,                     '2019-06-01/generated/azure_mgmt_storage/models/storage_account_update_parameters.rb'
    autoload :Usage,                                              '2019-06-01/generated/azure_mgmt_storage/models/usage.rb'
    autoload :PrivateLinkResourceListResult,                      '2019-06-01/generated/azure_mgmt_storage/models/private_link_resource_list_result.rb'
    autoload :AccountSasParameters,                               '2019-06-01/generated/azure_mgmt_storage/models/account_sas_parameters.rb'
    autoload :ErrorResponse,                                      '2019-06-01/generated/azure_mgmt_storage/models/error_response.rb'
    autoload :ServiceSasParameters,                               '2019-06-01/generated/azure_mgmt_storage/models/service_sas_parameters.rb'
    autoload :FileShareItems,                                     '2019-06-01/generated/azure_mgmt_storage/models/file_share_items.rb'
    autoload :ServiceSpecification,                               '2019-06-01/generated/azure_mgmt_storage/models/service_specification.rb'
    autoload :FileServiceItems,                                   '2019-06-01/generated/azure_mgmt_storage/models/file_service_items.rb'
    autoload :SKUCapability,                                      '2019-06-01/generated/azure_mgmt_storage/models/skucapability.rb'
    autoload :LeaseContainerResponse,                             '2019-06-01/generated/azure_mgmt_storage/models/lease_container_response.rb'
    autoload :StorageAccountCreateParameters,                     '2019-06-01/generated/azure_mgmt_storage/models/storage_account_create_parameters.rb'
    autoload :Resource,                                           '2019-06-01/generated/azure_mgmt_storage/models/resource.rb'
    autoload :DeleteRetentionPolicy,                              '2019-06-01/generated/azure_mgmt_storage/models/delete_retention_policy.rb'
    autoload :UpdateHistoryProperty,                              '2019-06-01/generated/azure_mgmt_storage/models/update_history_property.rb'
    autoload :StorageAccountRegenerateKeyParameters,              '2019-06-01/generated/azure_mgmt_storage/models/storage_account_regenerate_key_parameters.rb'
    autoload :ImmutabilityPolicyProperties,                       '2019-06-01/generated/azure_mgmt_storage/models/immutability_policy_properties.rb'
    autoload :UsageListResult,                                    '2019-06-01/generated/azure_mgmt_storage/models/usage_list_result.rb'
    autoload :TagProperty,                                        '2019-06-01/generated/azure_mgmt_storage/models/tag_property.rb'
    autoload :Dimension,                                          '2019-06-01/generated/azure_mgmt_storage/models/dimension.rb'
    autoload :LegalHoldProperties,                                '2019-06-01/generated/azure_mgmt_storage/models/legal_hold_properties.rb'
    autoload :AzureFilesIdentityBasedAuthentication,              '2019-06-01/generated/azure_mgmt_storage/models/azure_files_identity_based_authentication.rb'
    autoload :LeaseContainerRequest,                              '2019-06-01/generated/azure_mgmt_storage/models/lease_container_request.rb'
    autoload :StorageAccountListResult,                           '2019-06-01/generated/azure_mgmt_storage/models/storage_account_list_result.rb'
    autoload :BlobServiceItems,                                   '2019-06-01/generated/azure_mgmt_storage/models/blob_service_items.rb'
    autoload :ListAccountSasResponse,                             '2019-06-01/generated/azure_mgmt_storage/models/list_account_sas_response.rb'
    autoload :LegalHold,                                          '2019-06-01/generated/azure_mgmt_storage/models/legal_hold.rb'
    autoload :GeoReplicationStats,                                '2019-06-01/generated/azure_mgmt_storage/models/geo_replication_stats.rb'
    autoload :ChangeFeed,                                         '2019-06-01/generated/azure_mgmt_storage/models/change_feed.rb'
    autoload :OperationListResult,                                '2019-06-01/generated/azure_mgmt_storage/models/operation_list_result.rb'
    autoload :ListContainerItems,                                 '2019-06-01/generated/azure_mgmt_storage/models/list_container_items.rb'
    autoload :UsageName,                                          '2019-06-01/generated/azure_mgmt_storage/models/usage_name.rb'
    autoload :CorsRule,                                           '2019-06-01/generated/azure_mgmt_storage/models/cors_rule.rb'
    autoload :PrivateEndpointConnection,                          '2019-06-01/generated/azure_mgmt_storage/models/private_endpoint_connection.rb'
    autoload :StorageAccount,                                     '2019-06-01/generated/azure_mgmt_storage/models/storage_account.rb'
    autoload :ManagementPolicy,                                   '2019-06-01/generated/azure_mgmt_storage/models/management_policy.rb'
    autoload :PrivateLinkResource,                                '2019-06-01/generated/azure_mgmt_storage/models/private_link_resource.rb'
    autoload :ProxyResource,                                      '2019-06-01/generated/azure_mgmt_storage/models/proxy_resource.rb'
    autoload :TrackedResource,                                    '2019-06-01/generated/azure_mgmt_storage/models/tracked_resource.rb'
    autoload :AzureEntityResource,                                '2019-06-01/generated/azure_mgmt_storage/models/azure_entity_resource.rb'
    autoload :BlobContainer,                                      '2019-06-01/generated/azure_mgmt_storage/models/blob_container.rb'
    autoload :ImmutabilityPolicy,                                 '2019-06-01/generated/azure_mgmt_storage/models/immutability_policy.rb'
    autoload :ListContainerItem,                                  '2019-06-01/generated/azure_mgmt_storage/models/list_container_item.rb'
    autoload :BlobServiceProperties,                              '2019-06-01/generated/azure_mgmt_storage/models/blob_service_properties.rb'
    autoload :FileServiceProperties,                              '2019-06-01/generated/azure_mgmt_storage/models/file_service_properties.rb'
    autoload :FileShare,                                          '2019-06-01/generated/azure_mgmt_storage/models/file_share.rb'
    autoload :FileShareItem,                                      '2019-06-01/generated/azure_mgmt_storage/models/file_share_item.rb'
    autoload :ReasonCode,                                         '2019-06-01/generated/azure_mgmt_storage/models/reason_code.rb'
    autoload :SkuName,                                            '2019-06-01/generated/azure_mgmt_storage/models/sku_name.rb'
    autoload :SkuTier,                                            '2019-06-01/generated/azure_mgmt_storage/models/sku_tier.rb'
    autoload :Kind,                                               '2019-06-01/generated/azure_mgmt_storage/models/kind.rb'
    autoload :Reason,                                             '2019-06-01/generated/azure_mgmt_storage/models/reason.rb'
    autoload :KeySource,                                          '2019-06-01/generated/azure_mgmt_storage/models/key_source.rb'
    autoload :Action,                                             '2019-06-01/generated/azure_mgmt_storage/models/action.rb'
    autoload :State,                                              '2019-06-01/generated/azure_mgmt_storage/models/state.rb'
    autoload :Bypass,                                             '2019-06-01/generated/azure_mgmt_storage/models/bypass.rb'
    autoload :DefaultAction,                                      '2019-06-01/generated/azure_mgmt_storage/models/default_action.rb'
    autoload :DirectoryServiceOptions,                            '2019-06-01/generated/azure_mgmt_storage/models/directory_service_options.rb'
    autoload :AccessTier,                                         '2019-06-01/generated/azure_mgmt_storage/models/access_tier.rb'
    autoload :LargeFileSharesState,                               '2019-06-01/generated/azure_mgmt_storage/models/large_file_shares_state.rb'
    autoload :GeoReplicationStatus,                               '2019-06-01/generated/azure_mgmt_storage/models/geo_replication_status.rb'
    autoload :ProvisioningState,                                  '2019-06-01/generated/azure_mgmt_storage/models/provisioning_state.rb'
    autoload :AccountStatus,                                      '2019-06-01/generated/azure_mgmt_storage/models/account_status.rb'
    autoload :PrivateEndpointServiceConnectionStatus,             '2019-06-01/generated/azure_mgmt_storage/models/private_endpoint_service_connection_status.rb'
    autoload :PrivateEndpointConnectionProvisioningState,         '2019-06-01/generated/azure_mgmt_storage/models/private_endpoint_connection_provisioning_state.rb'
    autoload :KeyPermission,                                      '2019-06-01/generated/azure_mgmt_storage/models/key_permission.rb'
    autoload :UsageUnit,                                          '2019-06-01/generated/azure_mgmt_storage/models/usage_unit.rb'
    autoload :Services,                                           '2019-06-01/generated/azure_mgmt_storage/models/services.rb'
    autoload :SignedResourceTypes,                                '2019-06-01/generated/azure_mgmt_storage/models/signed_resource_types.rb'
    autoload :Permissions,                                        '2019-06-01/generated/azure_mgmt_storage/models/permissions.rb'
    autoload :HttpProtocol,                                       '2019-06-01/generated/azure_mgmt_storage/models/http_protocol.rb'
    autoload :SignedResource,                                     '2019-06-01/generated/azure_mgmt_storage/models/signed_resource.rb'
    autoload :PublicAccess,                                       '2019-06-01/generated/azure_mgmt_storage/models/public_access.rb'
    autoload :LeaseStatus,                                        '2019-06-01/generated/azure_mgmt_storage/models/lease_status.rb'
    autoload :LeaseState,                                         '2019-06-01/generated/azure_mgmt_storage/models/lease_state.rb'
    autoload :LeaseDuration,                                      '2019-06-01/generated/azure_mgmt_storage/models/lease_duration.rb'
    autoload :ImmutabilityPolicyState,                            '2019-06-01/generated/azure_mgmt_storage/models/immutability_policy_state.rb'
    autoload :ImmutabilityPolicyUpdateType,                       '2019-06-01/generated/azure_mgmt_storage/models/immutability_policy_update_type.rb'
    autoload :StorageAccountExpand,                               '2019-06-01/generated/azure_mgmt_storage/models/storage_account_expand.rb'
    autoload :ListKeyExpand,                                      '2019-06-01/generated/azure_mgmt_storage/models/list_key_expand.rb'
  end
end
