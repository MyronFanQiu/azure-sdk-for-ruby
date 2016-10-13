# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator 0.17.0.0
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
require 'generated/azure_mgmt_server_management/module_definition'
require 'ms_rest_azure'

module Azure::ARM::ServerManagement
  autoload :Gateway,                                            'generated/azure_mgmt_server_management/gateway.rb'
  autoload :Node,                                               'generated/azure_mgmt_server_management/node.rb'
  autoload :Session,                                            'generated/azure_mgmt_server_management/session.rb'
  autoload :PowerShell,                                         'generated/azure_mgmt_server_management/power_shell.rb'
  autoload :ServerManagement,                                   'generated/azure_mgmt_server_management/server_management.rb'

  module Models
    autoload :GatewayStatus,                                      'generated/azure_mgmt_server_management/models/gateway_status.rb'
    autoload :GatewayResources,                                   'generated/azure_mgmt_server_management/models/gateway_resources.rb'
    autoload :GatewayProfile,                                     'generated/azure_mgmt_server_management/models/gateway_profile.rb'
    autoload :GatewayParameters,                                  'generated/azure_mgmt_server_management/models/gateway_parameters.rb'
    autoload :NodeResources,                                      'generated/azure_mgmt_server_management/models/node_resources.rb'
    autoload :NodeParameters,                                     'generated/azure_mgmt_server_management/models/node_parameters.rb'
    autoload :SessionParameters,                                  'generated/azure_mgmt_server_management/models/session_parameters.rb'
    autoload :Version,                                            'generated/azure_mgmt_server_management/models/version.rb'
    autoload :PowerShellCommandResults,                           'generated/azure_mgmt_server_management/models/power_shell_command_results.rb'
    autoload :PowerShellCommandResult,                            'generated/azure_mgmt_server_management/models/power_shell_command_result.rb'
    autoload :PromptFieldDescription,                             'generated/azure_mgmt_server_management/models/prompt_field_description.rb'
    autoload :PowerShellSessionResources,                         'generated/azure_mgmt_server_management/models/power_shell_session_resources.rb'
    autoload :PowerShellCommandParameters,                        'generated/azure_mgmt_server_management/models/power_shell_command_parameters.rb'
    autoload :PromptMessageResponse,                              'generated/azure_mgmt_server_management/models/prompt_message_response.rb'
    autoload :PowerShellTabCompletionParameters,                  'generated/azure_mgmt_server_management/models/power_shell_tab_completion_parameters.rb'
    autoload :PowerShellTabCompletionResults,                     'generated/azure_mgmt_server_management/models/power_shell_tab_completion_results.rb'
    autoload :Error,                                              'generated/azure_mgmt_server_management/models/error.rb'
    autoload :GatewayResource,                                    'generated/azure_mgmt_server_management/models/gateway_resource.rb'
    autoload :NodeResource,                                       'generated/azure_mgmt_server_management/models/node_resource.rb'
    autoload :SessionResource,                                    'generated/azure_mgmt_server_management/models/session_resource.rb'
    autoload :PowerShellSessionResource,                          'generated/azure_mgmt_server_management/models/power_shell_session_resource.rb'
    autoload :PowerShellCommandStatus,                            'generated/azure_mgmt_server_management/models/power_shell_command_status.rb'
    autoload :AutoUpgrade,                                        'generated/azure_mgmt_server_management/models/auto_upgrade.rb'
    autoload :PromptFieldType,                                    'generated/azure_mgmt_server_management/models/prompt_field_type.rb'
    autoload :GatewayExpandOption,                                'generated/azure_mgmt_server_management/models/gateway_expand_option.rb'
    autoload :PowerShellExpandOption,                             'generated/azure_mgmt_server_management/models/power_shell_expand_option.rb'
  end
end