# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_06_01_5_1
  module Models
    #
    # The configuration for compute nodes in a pool based on the Azure Virtual
    # Machines infrastructure.
    #
    #
    class VirtualMachineConfiguration

      include MsRestAzure

      # @return [ImageReference] A reference to the Azure Virtual Machines
      # Marketplace image to use. This property and osDisk are mutually
      # exclusive and one of the properties must be specified.
      attr_accessor :image_reference

      # @return [OSDisk] A reference to the OS disk image to use. This property
      # can be specified only if the Batch account was created with its
      # poolAllocationMode property set to 'UserSubscription'. This property
      # and imageReference are mutually exclusive and one of the properties
      # must be specified.
      attr_accessor :os_disk

      # @return [String] The SKU of the Batch node agent to be provisioned on
      # compute nodes in the pool. The Batch node agent is a program that runs
      # on each node in the pool, and provides the command-and-control
      # interface between the node and the Batch service. There are different
      # implementations of the node agent, known as SKUs, for different
      # operating systems. You must specify a node agent SKU which matches the
      # selected image reference. To get the list of supported node agent SKUs
      # along with their list of verified image references, see the 'List
      # supported node agent SKUs' operation.
      attr_accessor :node_agent_skuid

      # @return [WindowsConfiguration] Windows operating system settings on the
      # virtual machine. This property must not be specified if the
      # imageReference or osDisk property specifies a Linux OS image.
      attr_accessor :windows_configuration


      #
      # Mapper for VirtualMachineConfiguration class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'VirtualMachineConfiguration',
          type: {
            name: 'Composite',
            class_name: 'VirtualMachineConfiguration',
            model_properties: {
              image_reference: {
                client_side_validation: true,
                required: false,
                serialized_name: 'imageReference',
                type: {
                  name: 'Composite',
                  class_name: 'ImageReference'
                }
              },
              os_disk: {
                client_side_validation: true,
                required: false,
                serialized_name: 'osDisk',
                type: {
                  name: 'Composite',
                  class_name: 'OSDisk'
                }
              },
              node_agent_skuid: {
                client_side_validation: true,
                required: true,
                serialized_name: 'nodeAgentSKUId',
                type: {
                  name: 'String'
                }
              },
              windows_configuration: {
                client_side_validation: true,
                required: false,
                serialized_name: 'windowsConfiguration',
                type: {
                  name: 'Composite',
                  class_name: 'WindowsConfiguration'
                }
              }
            }
          }
        }
      end
    end
  end
end
