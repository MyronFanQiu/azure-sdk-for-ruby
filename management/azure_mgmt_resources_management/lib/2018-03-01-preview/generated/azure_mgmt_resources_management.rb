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
require '2018-03-01-preview/generated/azure_mgmt_resources_management/module_definition'
require 'ms_rest_azure'

module Azure::ResourcesManagement::Mgmt::V2018_03_01_preview
  autoload :ManagementGroups,                                   '2018-03-01-preview/generated/azure_mgmt_resources_management/management_groups.rb'
  autoload :ManagementGroupSubscriptions,                       '2018-03-01-preview/generated/azure_mgmt_resources_management/management_group_subscriptions.rb'
  autoload :Operations,                                         '2018-03-01-preview/generated/azure_mgmt_resources_management/operations.rb'
  autoload :Entities,                                           '2018-03-01-preview/generated/azure_mgmt_resources_management/entities.rb'
  autoload :ManagementGroupsAPI,                                '2018-03-01-preview/generated/azure_mgmt_resources_management/management_groups_api.rb'

  module Models
    autoload :ManagementGroup,                                    '2018-03-01-preview/generated/azure_mgmt_resources_management/models/management_group.rb'
    autoload :ErrorDetails,                                       '2018-03-01-preview/generated/azure_mgmt_resources_management/models/error_details.rb'
    autoload :OperationResults,                                   '2018-03-01-preview/generated/azure_mgmt_resources_management/models/operation_results.rb'
    autoload :OperationDisplayProperties,                         '2018-03-01-preview/generated/azure_mgmt_resources_management/models/operation_display_properties.rb'
    autoload :EntityParentGroupInfo,                              '2018-03-01-preview/generated/azure_mgmt_resources_management/models/entity_parent_group_info.rb'
    autoload :OperationListResult,                                '2018-03-01-preview/generated/azure_mgmt_resources_management/models/operation_list_result.rb'
    autoload :EntityInfo,                                         '2018-03-01-preview/generated/azure_mgmt_resources_management/models/entity_info.rb'
    autoload :TenantBackfillStatusResult,                         '2018-03-01-preview/generated/azure_mgmt_resources_management/models/tenant_backfill_status_result.rb'
    autoload :EntityListResult,                                   '2018-03-01-preview/generated/azure_mgmt_resources_management/models/entity_list_result.rb'
    autoload :ManagementGroupListResult,                          '2018-03-01-preview/generated/azure_mgmt_resources_management/models/management_group_list_result.rb'
    autoload :EntityHierarchyItem,                                '2018-03-01-preview/generated/azure_mgmt_resources_management/models/entity_hierarchy_item.rb'
    autoload :ManagementGroupDetails,                             '2018-03-01-preview/generated/azure_mgmt_resources_management/models/management_group_details.rb'
    autoload :PatchManagementGroupRequest,                        '2018-03-01-preview/generated/azure_mgmt_resources_management/models/patch_management_group_request.rb'
    autoload :ErrorResponse,                                      '2018-03-01-preview/generated/azure_mgmt_resources_management/models/error_response.rb'
    autoload :CreateParentGroupInfo,                              '2018-03-01-preview/generated/azure_mgmt_resources_management/models/create_parent_group_info.rb'
    autoload :CheckNameAvailabilityResult,                        '2018-03-01-preview/generated/azure_mgmt_resources_management/models/check_name_availability_result.rb'
    autoload :CreateManagementGroupDetails,                       '2018-03-01-preview/generated/azure_mgmt_resources_management/models/create_management_group_details.rb'
    autoload :ParentGroupInfo,                                    '2018-03-01-preview/generated/azure_mgmt_resources_management/models/parent_group_info.rb'
    autoload :CreateManagementGroupChildInfo,                     '2018-03-01-preview/generated/azure_mgmt_resources_management/models/create_management_group_child_info.rb'
    autoload :Operation,                                          '2018-03-01-preview/generated/azure_mgmt_resources_management/models/operation.rb'
    autoload :CreateManagementGroupRequest,                       '2018-03-01-preview/generated/azure_mgmt_resources_management/models/create_management_group_request.rb'
    autoload :ManagementGroupChildInfo,                           '2018-03-01-preview/generated/azure_mgmt_resources_management/models/management_group_child_info.rb'
    autoload :CheckNameAvailabilityRequest,                       '2018-03-01-preview/generated/azure_mgmt_resources_management/models/check_name_availability_request.rb'
    autoload :ManagementGroupInfo,                                '2018-03-01-preview/generated/azure_mgmt_resources_management/models/management_group_info.rb'
    autoload :Reason,                                             '2018-03-01-preview/generated/azure_mgmt_resources_management/models/reason.rb'
    autoload :Status,                                             '2018-03-01-preview/generated/azure_mgmt_resources_management/models/status.rb'
    autoload :Type,                                               '2018-03-01-preview/generated/azure_mgmt_resources_management/models/type.rb'
  end
end