# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_09_01_6_0
  module Models
    #
    # A reference to an Azure Virtual Machines Marketplace image or a custom
    # Azure Virtual Machine image. To get the list of all Azure Marketplace
    # image references verified by Azure Batch, see the 'List node agent SKUs'
    # operation.
    #
    #
    class ImageReference

      include MsRestAzure

      # @return [String] The publisher of the Azure Virtual Machines
      # Marketplace image. For example, Canonical or MicrosoftWindowsServer.
      attr_accessor :publisher

      # @return [String] The offer type of the Azure Virtual Machines
      # Marketplace image. For example, UbuntuServer or WindowsServer.
      attr_accessor :offer

      # @return [String] The SKU of the Azure Virtual Machines Marketplace
      # image. For example, 14.04.0-LTS or 2012-R2-Datacenter.
      attr_accessor :sku

      # @return [String] The version of the Azure Virtual Machines Marketplace
      # image. A value of 'latest' can be specified to select the latest
      # version of an image. If omitted, the default is 'latest'.
      attr_accessor :version

      # @return [String] The ARM resource identifier of the virtual machine
      # image. Computes nodes of the pool will be created using this custom
      # image. This is of the form
      # /subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Compute/images/{imageName}.
      # This property is mutually exclusive with other ImageReference
      # properties. The virtual machine image must be in the same region and
      # subscription as the Azure Batch account. For information about the
      # firewall settings for the Batch node agent to communicate with the
      # Batch service see
      # https://docs.microsoft.com/en-us/azure/batch/batch-api-basics#virtual-network-vnet-and-firewall-configuration.
      attr_accessor :virtual_machine_image_id


      #
      # Mapper for ImageReference class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ImageReference',
          type: {
            name: 'Composite',
            class_name: 'ImageReference',
            model_properties: {
              publisher: {
                client_side_validation: true,
                required: false,
                serialized_name: 'publisher',
                type: {
                  name: 'String'
                }
              },
              offer: {
                client_side_validation: true,
                required: false,
                serialized_name: 'offer',
                type: {
                  name: 'String'
                }
              },
              sku: {
                client_side_validation: true,
                required: false,
                serialized_name: 'sku',
                type: {
                  name: 'String'
                }
              },
              version: {
                client_side_validation: true,
                required: false,
                serialized_name: 'version',
                type: {
                  name: 'String'
                }
              },
              virtual_machine_image_id: {
                client_side_validation: true,
                required: false,
                serialized_name: 'virtualMachineImageId',
                type: {
                  name: 'String'
                }
              }
            }
          }
        }
      end
    end
  end
end
