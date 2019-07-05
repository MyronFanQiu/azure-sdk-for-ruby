# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_09_01_6_0
  module Models
    #
    # The network configuration for a pool.
    #
    class NetworkConfiguration

      include MsRestAzure

      # @return [String] The ARM resource identifier of the virtual network
      # subnet which the compute nodes of the pool will join. This is of the
      # form
      # /subscriptions/{subscription}/resourceGroups/{group}/providers/{provider}/virtualNetworks/{network}/subnets/{subnet}.
      # The virtual network must be in the same region and subscription as the
      # Azure Batch account. The specified subnet should have enough free IP
      # addresses to accommodate the number of nodes in the pool. If the subnet
      # doesn't have enough free IP addresses, the pool will partially allocate
      # compute nodes, and a resize error will occur. The 'MicrosoftAzureBatch'
      # service principal must have the 'Classic Virtual Machine Contributor'
      # Role-Based Access Control (RBAC) role for the specified VNet. The
      # specified subnet must allow communication from the Azure Batch service
      # to be able to schedule tasks on the compute nodes. This can be verified
      # by checking if the specified VNet has any associated Network Security
      # Groups (NSG). If communication to the compute nodes in the specified
      # subnet is denied by an NSG, then the Batch service will set the state
      # of the compute nodes to unusable. For pools created with
      # virtualMachineConfiguration only ARM virtual networks
      # ('Microsoft.Network/virtualNetworks') are supported, but for pools
      # created with cloudServiceConfiguration both ARM and classic virtual
      # networks are supported. If the specified VNet has any associated
      # Network Security Groups (NSG), then a few reserved system ports must be
      # enabled for inbound communication. For pools created with a virtual
      # machine configuration, enable ports 29876 and 29877, as well as port 22
      # for Linux and port 3389 for Windows. For pools created with a cloud
      # service configuration, enable ports 10100, 20100, and 30100. Also
      # enable outbound connections to Azure Storage on port 443. For more
      # details see:
      # https://docs.microsoft.com/en-us/azure/batch/batch-api-basics#virtual-network-vnet-and-firewall-configuration
      attr_accessor :subnet_id

      # @return [PoolEndpointConfiguration] The configuration for endpoints on
      # compute nodes in the Batch pool. Pool endpoint configuration is only
      # supported on pools with the virtualMachineConfiguration property.
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
