# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::DevTestLabs::Mgmt::V2018_09_15
  module Models
    #
    # A formula for creating a VM, specifying an image base and other
    # parameters
    #
    class FormulaFragment < UpdateResource

      include MsRestAzure

      # @return [String] The description of the formula.
      attr_accessor :description

      # @return [String] The author of the formula.
      attr_accessor :author

      # @return [String] The OS type of the formula.
      attr_accessor :os_type

      # @return [LabVirtualMachineCreationParameterFragment] The content of the
      # formula.
      attr_accessor :formula_content

      # @return [FormulaPropertiesFromVmFragment] Information about a VM from
      # which a formula is to be created.
      attr_accessor :vm


      #
      # Mapper for FormulaFragment class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'FormulaFragment',
          type: {
            name: 'Composite',
            class_name: 'FormulaFragment',
            model_properties: {
              tags: {
                client_side_validation: true,
                required: false,
                serialized_name: 'tags',
                type: {
                  name: 'Dictionary',
                  value: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'StringElementType',
                      type: {
                        name: 'String'
                      }
                  }
                }
              },
              description: {
                client_side_validation: true,
                required: false,
                serialized_name: 'properties.description',
                type: {
                  name: 'String'
                }
              },
              author: {
                client_side_validation: true,
                required: false,
                serialized_name: 'properties.author',
                type: {
                  name: 'String'
                }
              },
              os_type: {
                client_side_validation: true,
                required: false,
                serialized_name: 'properties.osType',
                type: {
                  name: 'String'
                }
              },
              formula_content: {
                client_side_validation: true,
                required: false,
                serialized_name: 'properties.formulaContent',
                type: {
                  name: 'Composite',
                  class_name: 'LabVirtualMachineCreationParameterFragment'
                }
              },
              vm: {
                client_side_validation: true,
                required: false,
                serialized_name: 'properties.vm',
                type: {
                  name: 'Composite',
                  class_name: 'FormulaPropertiesFromVmFragment'
                }
              }
            }
          }
        }
      end
    end
  end
end