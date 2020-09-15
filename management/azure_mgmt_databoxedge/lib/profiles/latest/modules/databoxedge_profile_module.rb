# encoding: utf-8
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.

require 'azure_mgmt_databoxedge'

module Azure::DataBoxEdge::Profiles::Latest
  module Mgmt
    Operations = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Operations
    AvailableSkus = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::AvailableSkus
    Devices = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Devices
    Alerts = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Alerts
    BandwidthSchedules = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::BandwidthSchedules
    Jobs = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Jobs
    Nodes = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Nodes
    OperationsStatus = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::OperationsStatus
    Orders = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Orders
    Roles = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Roles
    Shares = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Shares
    StorageAccountCredentials = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::StorageAccountCredentials
    StorageAccounts = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::StorageAccounts
    Containers = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Containers
    Triggers = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Triggers
    Users = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Users
    Skus = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Skus

    module Models
      UpdateDownloadProgress = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::UpdateDownloadProgress
      UpdateInstallProgress = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::UpdateInstallProgress
      AlertErrorDetails = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::AlertErrorDetails
      Job = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Job
      AlertList = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::AlertList
      MetricDimensionV1 = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::MetricDimensionV1
      AsymmetricEncryptedSecret = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::AsymmetricEncryptedSecret
      MetricSpecificationV1 = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::MetricSpecificationV1
      Authentication = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Authentication
      NetworkAdapterPosition = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::NetworkAdapterPosition
      Ipv4Config = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Ipv4Config
      Ipv6Config = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Ipv6Config
      ClientAccessRight = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ClientAccessRight
      JobErrorItem = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::JobErrorItem
      JobErrorDetails = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::JobErrorDetails
      RefreshDetails = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::RefreshDetails
      Address = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Address
      ContainerList = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ContainerList
      Sku = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Sku
      UserAccessRight = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::UserAccessRight
      UploadCertificateRequest = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::UploadCertificateRequest
      ARMBaseModel = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ARMBaseModel
      DataBoxEdgeDevicePatch = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DataBoxEdgeDevicePatch
      SymmetricKey = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SymmetricKey
      SkuCost = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuCost
      AzureContainerInfo = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::AzureContainerInfo
      SkuRestriction = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuRestriction
      StorageAccountCredentialList = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::StorageAccountCredentialList
      DataBoxEdgeSkuList = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DataBoxEdgeSkuList
      NetworkAdapter = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::NetworkAdapter
      RoleSinkInfo = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::RoleSinkInfo
      SkuInformationList = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuInformationList
      ImageRepositoryCredential = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ImageRepositoryCredential
      SkuInformation = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuInformation
      IoTEdgeAgentInfo = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::IoTEdgeAgentInfo
      NodeList = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::NodeList
      StorageAccountList = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::StorageAccountList
      OperationDisplay = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::OperationDisplay
      ServiceSpecification = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ServiceSpecification
      UserList = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::UserList
      Operation = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Operation
      DataBoxEdgeDeviceList = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DataBoxEdgeDeviceList
      OperationsList = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::OperationsList
      SkuRestrictionInfo = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuRestrictionInfo
      OrderStatus = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::OrderStatus
      FileSourceInfo = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::FileSourceInfo
      TrackingInfo = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::TrackingInfo
      IoTDeviceInfo = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::IoTDeviceInfo
      SKUCost = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SKUCost
      BandwidthSchedulesList = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::BandwidthSchedulesList
      OrderList = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::OrderList
      UploadCertificateResponse = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::UploadCertificateResponse
      PeriodicTimerSourceInfo = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::PeriodicTimerSourceInfo
      DataBoxEdgeSku = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DataBoxEdgeSku
      SKUCapability = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SKUCapability
      MountPointMap = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::MountPointMap
      ResourceTypeSku = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ResourceTypeSku
      SkuLocationInfo = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuLocationInfo
      ShareList = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ShareList
      ContactDetails = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ContactDetails
      RoleList = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::RoleList
      TriggerList = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::TriggerList
      ShareAccessRight = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ShareAccessRight
      Alert = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Alert
      BandwidthSchedule = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::BandwidthSchedule
      Container = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Container
      DataBoxEdgeDevice = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DataBoxEdgeDevice
      DataBoxEdgeDeviceExtendedInfo = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DataBoxEdgeDeviceExtendedInfo
      FileEventTrigger = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::FileEventTrigger
      IoTRole = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::IoTRole
      NetworkSettings = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::NetworkSettings
      Node = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Node
      Order = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Order
      PeriodicTimerEventTrigger = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::PeriodicTimerEventTrigger
      Role = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Role
      SecuritySettings = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SecuritySettings
      Share = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Share
      StorageAccount = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::StorageAccount
      StorageAccountCredential = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::StorageAccountCredential
      Trigger = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Trigger
      UpdateSummary = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::UpdateSummary
      User = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::User
      AlertSeverity = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::AlertSeverity
      EncryptionAlgorithm = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::EncryptionAlgorithm
      AzureContainerDataFormat = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::AzureContainerDataFormat
      DayOfWeek = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DayOfWeek
      ClientPermissionType = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ClientPermissionType
      ContainerStatus = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ContainerStatus
      SkuName = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuName
      SkuTier = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuTier
      DataBoxEdgeDeviceStatus = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DataBoxEdgeDeviceStatus
      DeviceType = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DeviceType
      RoleTypes = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::RoleTypes
      SkuRestrictionReasonCode = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuRestrictionReasonCode
      SkuSignupOption = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuSignupOption
      SkuVersion = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuVersion
      SkuAvailability = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuAvailability
      PlatformType = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::PlatformType
      MountType = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::MountType
      HostPlatformType = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::HostPlatformType
      RoleStatus = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::RoleStatus
      JobStatus = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::JobStatus
      JobType = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::JobType
      UpdateOperationStage = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::UpdateOperationStage
      DownloadPhase = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DownloadPhase
      MetricUnit = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::MetricUnit
      MetricAggregationType = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::MetricAggregationType
      MetricCategory = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::MetricCategory
      TimeGrain = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::TimeGrain
      NetworkGroup = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::NetworkGroup
      NetworkAdapterStatus = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::NetworkAdapterStatus
      NetworkAdapterRDMAStatus = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::NetworkAdapterRDMAStatus
      NetworkAdapterDHCPStatus = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::NetworkAdapterDHCPStatus
      NodeStatus = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::NodeStatus
      OrderState = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::OrderState
      AuthenticationType = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::AuthenticationType
      ShareStatus = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ShareStatus
      MonitoringStatus = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::MonitoringStatus
      ShareAccessProtocol = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ShareAccessProtocol
      ShareAccessType = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ShareAccessType
      DataPolicy = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DataPolicy
      StorageAccountStatus = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::StorageAccountStatus
      SSLStatus = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SSLStatus
      AccountType = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::AccountType
      InstallRebootBehavior = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::InstallRebootBehavior
      UpdateOperation = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::UpdateOperation
      UserType = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::UserType
    end

    #
    # DataBoxEdgeManagementClass
    #
    class DataBoxEdgeManagementClass
      attr_reader :operations, :available_skus, :devices, :alerts, :bandwidth_schedules, :jobs, :nodes, :operations_status, :orders, :roles, :shares, :storage_account_credentials, :storage_accounts, :containers, :triggers, :users, :skus, :configurable, :base_url, :options, :model_classes

      def initialize(options = {})
        if options.is_a?(Hash) && options.length == 0
          @options = setup_default_options
        else
          @options = options
        end

        reset!(options)

        @configurable = self
        @base_url = options[:base_url].nil? ? nil:options[:base_url]
        @options = options[:options].nil? ? nil:options[:options]

        @client_0 = Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::DataBoxEdgeManagementClient.new(configurable.credentials, base_url, options)
        if(@client_0.respond_to?(:subscription_id))
          @client_0.subscription_id = configurable.subscription_id
        end
        add_telemetry(@client_0)
        @operations = @client_0.operations
        @available_skus = @client_0.available_skus
        @devices = @client_0.devices
        @alerts = @client_0.alerts
        @bandwidth_schedules = @client_0.bandwidth_schedules
        @jobs = @client_0.jobs
        @nodes = @client_0.nodes
        @operations_status = @client_0.operations_status
        @orders = @client_0.orders
        @roles = @client_0.roles
        @shares = @client_0.shares
        @storage_account_credentials = @client_0.storage_account_credentials
        @storage_accounts = @client_0.storage_accounts
        @containers = @client_0.containers
        @triggers = @client_0.triggers
        @users = @client_0.users
        @skus = @client_0.skus

        @model_classes = ModelClasses.new
      end

      def add_telemetry(client)
        profile_information = 'Profiles/Latest/DataBoxEdge/Mgmt'
        client.add_user_agent_information(profile_information)
      end

      def method_missing(method, *args)
        if @client_0.respond_to?method
          @client_0.send(method, *args)
        else
          super
        end
      end

    end

    class ModelClasses
      def update_download_progress
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::UpdateDownloadProgress
      end
      def update_install_progress
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::UpdateInstallProgress
      end
      def alert_error_details
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::AlertErrorDetails
      end
      def job
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Job
      end
      def alert_list
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::AlertList
      end
      def metric_dimension_v1
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::MetricDimensionV1
      end
      def asymmetric_encrypted_secret
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::AsymmetricEncryptedSecret
      end
      def metric_specification_v1
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::MetricSpecificationV1
      end
      def authentication
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Authentication
      end
      def network_adapter_position
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::NetworkAdapterPosition
      end
      def ipv4_config
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Ipv4Config
      end
      def ipv6_config
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Ipv6Config
      end
      def client_access_right
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ClientAccessRight
      end
      def job_error_item
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::JobErrorItem
      end
      def job_error_details
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::JobErrorDetails
      end
      def refresh_details
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::RefreshDetails
      end
      def address
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Address
      end
      def container_list
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ContainerList
      end
      def sku
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Sku
      end
      def user_access_right
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::UserAccessRight
      end
      def upload_certificate_request
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::UploadCertificateRequest
      end
      def armbase_model
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ARMBaseModel
      end
      def data_box_edge_device_patch
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DataBoxEdgeDevicePatch
      end
      def symmetric_key
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SymmetricKey
      end
      def sku_cost
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuCost
      end
      def azure_container_info
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::AzureContainerInfo
      end
      def sku_restriction
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuRestriction
      end
      def storage_account_credential_list
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::StorageAccountCredentialList
      end
      def data_box_edge_sku_list
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DataBoxEdgeSkuList
      end
      def network_adapter
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::NetworkAdapter
      end
      def role_sink_info
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::RoleSinkInfo
      end
      def sku_information_list
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuInformationList
      end
      def image_repository_credential
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ImageRepositoryCredential
      end
      def sku_information
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuInformation
      end
      def io_tedge_agent_info
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::IoTEdgeAgentInfo
      end
      def node_list
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::NodeList
      end
      def storage_account_list
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::StorageAccountList
      end
      def operation_display
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::OperationDisplay
      end
      def service_specification
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ServiceSpecification
      end
      def user_list
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::UserList
      end
      def operation
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Operation
      end
      def data_box_edge_device_list
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DataBoxEdgeDeviceList
      end
      def operations_list
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::OperationsList
      end
      def sku_restriction_info
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuRestrictionInfo
      end
      def order_status
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::OrderStatus
      end
      def file_source_info
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::FileSourceInfo
      end
      def tracking_info
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::TrackingInfo
      end
      def io_tdevice_info
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::IoTDeviceInfo
      end
      def skucost
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SKUCost
      end
      def bandwidth_schedules_list
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::BandwidthSchedulesList
      end
      def order_list
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::OrderList
      end
      def upload_certificate_response
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::UploadCertificateResponse
      end
      def periodic_timer_source_info
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::PeriodicTimerSourceInfo
      end
      def data_box_edge_sku
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DataBoxEdgeSku
      end
      def skucapability
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SKUCapability
      end
      def mount_point_map
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::MountPointMap
      end
      def resource_type_sku
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ResourceTypeSku
      end
      def sku_location_info
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuLocationInfo
      end
      def share_list
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ShareList
      end
      def contact_details
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ContactDetails
      end
      def role_list
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::RoleList
      end
      def trigger_list
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::TriggerList
      end
      def share_access_right
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ShareAccessRight
      end
      def alert
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Alert
      end
      def bandwidth_schedule
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::BandwidthSchedule
      end
      def container
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Container
      end
      def data_box_edge_device
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DataBoxEdgeDevice
      end
      def data_box_edge_device_extended_info
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DataBoxEdgeDeviceExtendedInfo
      end
      def file_event_trigger
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::FileEventTrigger
      end
      def io_trole
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::IoTRole
      end
      def network_settings
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::NetworkSettings
      end
      def node
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Node
      end
      def order
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Order
      end
      def periodic_timer_event_trigger
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::PeriodicTimerEventTrigger
      end
      def role
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Role
      end
      def security_settings
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SecuritySettings
      end
      def share
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Share
      end
      def storage_account
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::StorageAccount
      end
      def storage_account_credential
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::StorageAccountCredential
      end
      def trigger
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::Trigger
      end
      def update_summary
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::UpdateSummary
      end
      def user
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::User
      end
      def alert_severity
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::AlertSeverity
      end
      def encryption_algorithm
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::EncryptionAlgorithm
      end
      def azure_container_data_format
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::AzureContainerDataFormat
      end
      def day_of_week
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DayOfWeek
      end
      def client_permission_type
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ClientPermissionType
      end
      def container_status
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ContainerStatus
      end
      def sku_name
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuName
      end
      def sku_tier
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuTier
      end
      def data_box_edge_device_status
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DataBoxEdgeDeviceStatus
      end
      def device_type
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DeviceType
      end
      def role_types
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::RoleTypes
      end
      def sku_restriction_reason_code
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuRestrictionReasonCode
      end
      def sku_signup_option
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuSignupOption
      end
      def sku_version
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuVersion
      end
      def sku_availability
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SkuAvailability
      end
      def platform_type
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::PlatformType
      end
      def mount_type
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::MountType
      end
      def host_platform_type
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::HostPlatformType
      end
      def role_status
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::RoleStatus
      end
      def job_status
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::JobStatus
      end
      def job_type
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::JobType
      end
      def update_operation_stage
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::UpdateOperationStage
      end
      def download_phase
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DownloadPhase
      end
      def metric_unit
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::MetricUnit
      end
      def metric_aggregation_type
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::MetricAggregationType
      end
      def metric_category
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::MetricCategory
      end
      def time_grain
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::TimeGrain
      end
      def network_group
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::NetworkGroup
      end
      def network_adapter_status
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::NetworkAdapterStatus
      end
      def network_adapter_rdmastatus
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::NetworkAdapterRDMAStatus
      end
      def network_adapter_dhcpstatus
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::NetworkAdapterDHCPStatus
      end
      def node_status
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::NodeStatus
      end
      def order_state
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::OrderState
      end
      def authentication_type
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::AuthenticationType
      end
      def share_status
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ShareStatus
      end
      def monitoring_status
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::MonitoringStatus
      end
      def share_access_protocol
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ShareAccessProtocol
      end
      def share_access_type
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::ShareAccessType
      end
      def data_policy
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::DataPolicy
      end
      def storage_account_status
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::StorageAccountStatus
      end
      def sslstatus
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::SSLStatus
      end
      def account_type
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::AccountType
      end
      def install_reboot_behavior
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::InstallRebootBehavior
      end
      def update_operation
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::UpdateOperation
      end
      def user_type
        Azure::DataBoxEdge::Mgmt::V2020_05_01_preview::Models::UserType
      end
    end
  end
end
