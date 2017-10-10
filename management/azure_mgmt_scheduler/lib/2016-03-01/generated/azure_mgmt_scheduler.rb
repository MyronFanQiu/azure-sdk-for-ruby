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
require '2016-03-01/generated/azure_mgmt_scheduler/module_definition'
require 'ms_rest_azure'

module Azure::ARM::Scheduler::Api_2016_03_01
  autoload :JobCollections,                                     '2016-03-01/generated/azure_mgmt_scheduler/job_collections.rb'
  autoload :Jobs,                                               '2016-03-01/generated/azure_mgmt_scheduler/jobs.rb'
  autoload :SchedulerManagementClient,                          '2016-03-01/generated/azure_mgmt_scheduler/scheduler_management_client.rb'

  module Models
    autoload :JobRecurrence,                                      '2016-03-01/generated/azure_mgmt_scheduler/models/job_recurrence.rb'
    autoload :Sku,                                                '2016-03-01/generated/azure_mgmt_scheduler/models/sku.rb'
    autoload :JobStatus,                                          '2016-03-01/generated/azure_mgmt_scheduler/models/job_status.rb'
    autoload :JobCollectionQuota,                                 '2016-03-01/generated/azure_mgmt_scheduler/models/job_collection_quota.rb'
    autoload :JobProperties,                                      '2016-03-01/generated/azure_mgmt_scheduler/models/job_properties.rb'
    autoload :JobCollectionDefinition,                            '2016-03-01/generated/azure_mgmt_scheduler/models/job_collection_definition.rb'
    autoload :JobDefinition,                                      '2016-03-01/generated/azure_mgmt_scheduler/models/job_definition.rb'
    autoload :HttpAuthentication,                                 '2016-03-01/generated/azure_mgmt_scheduler/models/http_authentication.rb'
    autoload :JobListResult,                                      '2016-03-01/generated/azure_mgmt_scheduler/models/job_list_result.rb'
    autoload :StorageQueueMessage,                                '2016-03-01/generated/azure_mgmt_scheduler/models/storage_queue_message.rb'
    autoload :JobHistoryDefinitionProperties,                     '2016-03-01/generated/azure_mgmt_scheduler/models/job_history_definition_properties.rb'
    autoload :HttpRequest,                                        '2016-03-01/generated/azure_mgmt_scheduler/models/http_request.rb'
    autoload :RetryPolicy,                                        '2016-03-01/generated/azure_mgmt_scheduler/models/retry_policy.rb'
    autoload :ServiceBusBrokeredMessageProperties,                '2016-03-01/generated/azure_mgmt_scheduler/models/service_bus_brokered_message_properties.rb'
    autoload :JobAction,                                          '2016-03-01/generated/azure_mgmt_scheduler/models/job_action.rb'
    autoload :JobRecurrenceSchedule,                              '2016-03-01/generated/azure_mgmt_scheduler/models/job_recurrence_schedule.rb'
    autoload :JobHistoryDefinition,                               '2016-03-01/generated/azure_mgmt_scheduler/models/job_history_definition.rb'
    autoload :JobCollectionProperties,                            '2016-03-01/generated/azure_mgmt_scheduler/models/job_collection_properties.rb'
    autoload :JobHistoryListResult,                               '2016-03-01/generated/azure_mgmt_scheduler/models/job_history_list_result.rb'
    autoload :JobErrorAction,                                     '2016-03-01/generated/azure_mgmt_scheduler/models/job_error_action.rb'
    autoload :JobHistoryFilter,                                   '2016-03-01/generated/azure_mgmt_scheduler/models/job_history_filter.rb'
    autoload :JobMaxRecurrence,                                   '2016-03-01/generated/azure_mgmt_scheduler/models/job_max_recurrence.rb'
    autoload :JobStateFilter,                                     '2016-03-01/generated/azure_mgmt_scheduler/models/job_state_filter.rb'
    autoload :JobRecurrenceScheduleMonthlyOccurrence,             '2016-03-01/generated/azure_mgmt_scheduler/models/job_recurrence_schedule_monthly_occurrence.rb'
    autoload :ServiceBusMessage,                                  '2016-03-01/generated/azure_mgmt_scheduler/models/service_bus_message.rb'
    autoload :JobCollectionListResult,                            '2016-03-01/generated/azure_mgmt_scheduler/models/job_collection_list_result.rb'
    autoload :ServiceBusAuthentication,                           '2016-03-01/generated/azure_mgmt_scheduler/models/service_bus_authentication.rb'
    autoload :ServiceBusQueueMessage,                             '2016-03-01/generated/azure_mgmt_scheduler/models/service_bus_queue_message.rb'
    autoload :ServiceBusTopicMessage,                             '2016-03-01/generated/azure_mgmt_scheduler/models/service_bus_topic_message.rb'
    autoload :ClientCertAuthentication,                           '2016-03-01/generated/azure_mgmt_scheduler/models/client_cert_authentication.rb'
    autoload :BasicAuthentication,                                '2016-03-01/generated/azure_mgmt_scheduler/models/basic_authentication.rb'
    autoload :OAuthAuthentication,                                '2016-03-01/generated/azure_mgmt_scheduler/models/oauth_authentication.rb'
    autoload :SkuDefinition,                                      '2016-03-01/generated/azure_mgmt_scheduler/models/sku_definition.rb'
    autoload :JobCollectionState,                                 '2016-03-01/generated/azure_mgmt_scheduler/models/job_collection_state.rb'
    autoload :RecurrenceFrequency,                                '2016-03-01/generated/azure_mgmt_scheduler/models/recurrence_frequency.rb'
    autoload :JobActionType,                                      '2016-03-01/generated/azure_mgmt_scheduler/models/job_action_type.rb'
    autoload :HttpAuthenticationType,                             '2016-03-01/generated/azure_mgmt_scheduler/models/http_authentication_type.rb'
    autoload :RetryType,                                          '2016-03-01/generated/azure_mgmt_scheduler/models/retry_type.rb'
    autoload :DayOfWeek,                                          '2016-03-01/generated/azure_mgmt_scheduler/models/day_of_week.rb'
    autoload :JobScheduleDay,                                     '2016-03-01/generated/azure_mgmt_scheduler/models/job_schedule_day.rb'
    autoload :JobState,                                           '2016-03-01/generated/azure_mgmt_scheduler/models/job_state.rb'
    autoload :JobHistoryActionName,                               '2016-03-01/generated/azure_mgmt_scheduler/models/job_history_action_name.rb'
    autoload :JobExecutionStatus,                                 '2016-03-01/generated/azure_mgmt_scheduler/models/job_execution_status.rb'
    autoload :ServiceBusAuthenticationType,                       '2016-03-01/generated/azure_mgmt_scheduler/models/service_bus_authentication_type.rb'
    autoload :ServiceBusTransportType,                            '2016-03-01/generated/azure_mgmt_scheduler/models/service_bus_transport_type.rb'
  end
end