# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2019_06_01_9_0
  module Models
    #
    # The network configuration for a Pool.
    #
    class NetworkConfiguration

      include MsRestAzure

      # @return [String] The ARM resource identifier of the virtual network
      # subnet which the Compute Nodes of the Pool will join. This is of the
      # form
      # /subscriptions/{subscription}/resourceGroups/{group}/providers/{provider}/virtualNetworks/{network}/subnets/{subnet}.
      # The virtual network must be in the same region and subscription as the
      # Azure Batch Account. The specified subnet should have enough free IP
      # addresses to accommodate the number of Compute Nodes in the Pool. If
      # the subnet doesn't have enough free IP addresses, the Pool will
      # partially allocate Nodes, and a resize error will occur. The
      # 'MicrosoftAzureBatch' service principal must have the 'Classic Virtual
      # Machine Contributor' Role-Based Access Control (RBAC) role for the
      # specified VNet. The specified subnet must allow communication from the
      # Azure Batch service to be able to schedule Tasks on the Nodes. This can
      # be verified by checking if the specified VNet has any associated
      # Network Security Groups (NSG). If communication to the Nodes in the
      # specified subnet is denied by an NSG, then the Batch service will set
      # the state of the Compute Nodes to unusable. For Pools created with
      # virtualMachineConfiguration only ARM virtual networks
      # ('Microsoft.Network/virtualNetworks') are supported, but for Pools
      # created with cloudServiceConfiguration both ARM and classic virtual
      # networks are supported. If the specified VNet has any associated
      # Network Security Groups (NSG), then a few reserved system ports must be
      # enabled for inbound communication. For Pools created with a virtual
      # machine configuration, enable ports 29876 and 29877, as well as port 22
      # for Linux and port 3389 for Windows. For Pools created with a cloud
      # service configuration, enable ports 10100, 20100, and 30100. Also
      # enable outbound connections to Azure Storage on port 443. For more
      # details see:
      # https://docs.microsoft.com/en-us/azure/batch/batch-api-basics#virtual-network-vnet-and-firewall-configuration
      attr_accessor :subnet_id

      # @return [DynamicVNetAssignmentScope] The scope of dynamic vnet
      # assignment. Possible values include: 'none', 'job'
      attr_accessor :dynamic_vnet_assignment_scope

      # @return [PoolEndpointConfiguration] The configuration for endpoints on
      # Compute Nodes in the Batch Pool. Pool endpoint configuration is only
      # supported on Pools with the virtualMachineConfiguration property.
      attr_accessor :endpoint_configuration


      #
      # Mapper for NetworkConfiguration class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'NetworkConfiguration',
          type: {
            name: 'Composite',
            class_name: 'NetworkConfiguration',
            model_properties: {
              subnet_id: {
                client_side_validation: true,
                required: false,
                serialized_name: 'subnetId',
                type: {
                  name: 'String'
                }
              },
              dynamic_vnet_assignment_scope: {
                client_side_validation: true,
                required: false,
                serialized_name: 'dynamicVNetAssignmentScope',
                type: {
                  name: 'Enum',
                  module: 'DynamicVNetAssignmentScope'
                }
              },
              endpoint_configuration: {
                client_side_validation: true,
                required: false,
                serialized_name: 'endpointConfiguration',
                type: {
                  name: 'Composite',
                  class_name: 'PoolEndpointConfiguration'
                }
              }
            }
          }
        }
      end
    end
  end
end