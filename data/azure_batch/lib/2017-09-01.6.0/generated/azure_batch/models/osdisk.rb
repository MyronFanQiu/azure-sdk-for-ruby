# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_09_01_6_0
  module Models
    #
    # Settings for the operating system disk of the virtual machine.
    #
    #
    class OSDisk

      include MsRestAzure

      # @return [CachingType] The type of caching to enable for the OS disk.
      # The default value for caching is none. For information about the
      # caching options see:
      # https://blogs.msdn.microsoft.com/windowsazurestorage/2012/06/27/exploring-windows-azure-drives-disks-and-images/.
      # Possible values include: 'none', 'readOnly', 'readWrite'
      attr_accessor :caching


      #
      # Mapper for OSDisk class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'OSDisk',
          type: {
            name: 'Composite',
            class_name: 'OSDisk',
            model_properties: {
              caching: {
                client_side_validation: true,
                required: false,
                serialized_name: 'caching',
                type: {
                  name: 'Enum',
                  module: 'CachingType'
                }
              }
            }
          }
        }
      end
    end
  end
end
